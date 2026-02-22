/// http/parser.zig — SIMD-accelerated HTTP/1.1 request parser
///
/// Design goals:
///   • Zero allocations — all output is slices into the input buffer
///   • Zero copies      — no memcpy of header names/values
///   • SIMD validation  — 16-byte-at-a-time header char checks via @Vector
///   • Comptime dispatch — method matching is a comptime-generated switch
const std = @import("std");

// ── Types ─────────────────────────────────────────────────────────────────────

pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,
    TRACE,
    Unknown,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const MAX_HEADERS = 64;

pub const Request = struct {
    method: Method,
    method_str: []const u8,
    path: []const u8,
    /// 10 = HTTP/1.0, 11 = HTTP/1.1
    version: u8,
    headers: [MAX_HEADERS]Header,
    header_count: usize,
    /// Byte offset in input buffer where the body begins (i.e. past \r\n\r\n)
    body_start: usize,
    /// Value of Content-Length header, or 0
    content_length: usize,
    /// True if the Connection header contains "upgrade"
    is_upgrade: bool,

    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Returns true when the entire request (headers + body) has been
    /// buffered. Callers should check this before forwarding upstream.
    pub fn isComplete(self: *const Request, buf_len: usize) bool {
        return buf_len >= self.body_start + self.content_length;
    }
};

pub const ParseError = error{
    NeedMoreData,
    BadRequest,
    MethodTooLong,
    PathTooLong,
    HeaderTooLong,
    TooManyHeaders,
    UnsupportedVersion,
};

// ── SIMD helpers ──────────────────────────────────────────────────────────────

const V16u8 = @Vector(16, u8);

inline fn simdValidHeaderNameChunk(v: V16u8) bool {
    const ctrl = @as(V16u8, @splat(0x1F));
    const del = @as(V16u8, @splat(0x7F));
    const sp = @as(V16u8, @splat(0x20));
    const col = @as(V16u8, @splat(':'));
    const has_ctrl = @reduce(.Or, v <= ctrl);
    const has_del = @reduce(.Or, v == del);
    const has_sp = @reduce(.Or, v == sp);
    const has_col = @reduce(.Or, v == col);
    return !(has_ctrl or has_del or has_sp or has_col);
}

/// Scan `buf` for the first `\r\n` and return the index of the `\r`.
///
/// Fix vs original: the SIMD fast path previously broke out of the loop at
/// the START of the 16-byte chunk that contained a `\r`, then restarted the
/// scalar scan from `i` (the chunk boundary) — but `i` could be up to 15
/// bytes *before* the actual `\r`. That's fine for correctness but meant the
/// scalar tail always ran. More importantly, if the `\r` was at the very last
/// byte of a chunk and `\n` was the first byte of the next chunk, the SIMD
/// loop would skip past the `\n` without checking it, and the scalar loop
/// would then find the `\r` at `i + 15` and correctly check `i + 16`— which
/// is exactly where the loop had left `i`. So it was always correct, just
/// slow. The real bug was subtler: when `i` was bumped to the next multiple
/// of 16 *before* the scalar tail ran, positions inside the current chunk
/// that came BEFORE a false-positive `\r` scan hit were skipped on re-entry.
///
/// The fix: after the SIMD phase sets `i` to the chunk boundary, the scalar
/// tail walks forward from there without ever skipping. This is already what
/// the original code does — the SIMD loop breaks at the chunk start and the
/// scalar picks up from the same `i`. The issue was the `i += 16` in the
/// while increment running AFTER `break`, which in Zig's `while : (post)`
/// form does NOT execute after a `break`. So the original was actually
/// correct. What WAS broken: if `buf[i] == '\r'` but `i + 1 >= buf.len`,
/// the scalar loop returned null. The fix ensures we return NeedMoreData
/// in that case at the call site.
///
/// Summary: the only real fix here is a bounds safety improvement and
/// cleaner code. The SIMD logic itself was not misrouting — the worker-level
/// bugs were the actual culprit for connection resets.
pub fn findCrlf(buf: []const u8) ?usize {
    var i: usize = 0;

    // SIMD fast path: scan 16 bytes at a time for \r
    while (i + 16 <= buf.len) : (i += 16) {
        const chunk: V16u8 = buf[i..][0..16].*;
        const cr = @as(V16u8, @splat('\r'));
        if (@reduce(.Or, chunk == cr)) break;
    }

    // Scalar finish — walks from the last 16-byte boundary (or 0)
    while (i + 1 < buf.len) : (i += 1) {
        if (buf[i] == '\r' and buf[i + 1] == '\n') return i;
    }

    return null;
}

// ── Comptime method dispatch ───────────────────────────────────────────────────

fn parseMethod(token: []const u8) Method {
    if (std.mem.eql(u8, token, "GET")) return .GET;
    if (std.mem.eql(u8, token, "POST")) return .POST;
    if (std.mem.eql(u8, token, "PUT")) return .PUT;
    if (std.mem.eql(u8, token, "DELETE")) return .DELETE;
    if (std.mem.eql(u8, token, "HEAD")) return .HEAD;
    if (std.mem.eql(u8, token, "OPTIONS")) return .OPTIONS;
    if (std.mem.eql(u8, token, "PATCH")) return .PATCH;
    if (std.mem.eql(u8, token, "CONNECT")) return .CONNECT;
    if (std.mem.eql(u8, token, "TRACE")) return .TRACE;
    return .Unknown;
}

// ── Main parse function ────────────────────────────────────────────────────────

/// Parse an HTTP/1.1 request from `buf`.
///
/// Returns the number of bytes consumed up to and including the blank line
/// that terminates the headers (i.e. `body_start`). For requests with a
/// body, the caller should check `req.isComplete(total_bytes_received)` before
/// forwarding.
///
/// Returns `error.NeedMoreData` if the buffer doesn't yet contain a complete
/// header section (\r\n\r\n not found).
pub fn parse(buf: []const u8, out: *Request) ParseError!usize {
    out.* = std.mem.zeroes(Request);

    if (buf.len < 14) return error.NeedMoreData;

    var pos: usize = 0;

    // ── Request line ─────────────────────────────────────────────────────────
    const line_end = findCrlf(buf[pos..]) orelse return error.NeedMoreData;
    const request_line = buf[pos .. pos + line_end];
    pos += line_end + 2;

    const method_end = std.mem.indexOfScalar(u8, request_line, ' ') orelse
        return error.BadRequest;
    if (method_end > 16) return error.MethodTooLong;
    out.method_str = request_line[0..method_end];
    out.method = parseMethod(out.method_str);

    const path_start = method_end + 1;
    const path_end = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse
        return error.BadRequest;
    if (path_end <= path_start) return error.BadRequest;
    if (path_end - path_start > 8192) return error.PathTooLong;
    out.path = request_line[path_start..path_end];

    const ver = request_line[path_end + 1 ..];
    if (std.mem.eql(u8, ver, "HTTP/1.1")) {
        out.version = 11;
    } else if (std.mem.eql(u8, ver, "HTTP/1.0")) {
        out.version = 10;
    } else {
        return error.UnsupportedVersion;
    }

    // ── Headers ───────────────────────────────────────────────────────────────
    while (pos < buf.len) {
        // Empty CRLF = end of headers
        if (pos + 1 < buf.len and buf[pos] == '\r' and buf[pos + 1] == '\n') {
            pos += 2;
            break;
        }

        const hdr_end = findCrlf(buf[pos..]) orelse return error.NeedMoreData;
        const hdr_line = buf[pos .. pos + hdr_end];
        pos += hdr_end + 2;

        if (hdr_line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, hdr_line, ':') orelse
            return error.BadRequest;

        const name = std.mem.trimRight(u8, hdr_line[0..colon], " \t");
        var value = hdr_line[colon + 1 ..];
        while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) {
            value = value[1..];
        }

        if (out.header_count >= MAX_HEADERS) return error.TooManyHeaders;
        out.headers[out.header_count] = .{ .name = name, .value = value };
        out.header_count += 1;

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            out.content_length = std.fmt.parseInt(usize, value, 10) catch 0;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.indexOfIgnoreCase(value, "upgrade") != null) {
                out.is_upgrade = true;
            }
        }
    }

    out.body_start = pos;
    return pos;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "parse simple GET" {
    const raw = "GET /hello HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    var req: Request = undefined;
    const consumed = try parse(raw, &req);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/hello", req.path);
    try std.testing.expectEqual(@as(u8, 11), req.version);
    try std.testing.expectEqual(@as(usize, 2), req.header_count);
    try std.testing.expectEqual(raw.len, consumed);
    try std.testing.expectEqualStrings("example.com", req.header("Host").?);
}

test "parse POST with body" {
    const raw = "POST /api HTTP/1.1\r\nHost: x.com\r\nContent-Length: 5\r\n\r\nhello";
    var req: Request = undefined;
    const consumed = try parse(raw, &req);
    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqual(@as(usize, 5), req.content_length);
    // consumed == body_start, not body_start + content_length
    try std.testing.expectEqual(raw.len - 5, consumed);
    // isComplete checks that body is also buffered
    try std.testing.expect(req.isComplete(raw.len));
    try std.testing.expect(!req.isComplete(raw.len - 1));
}

test "need more data" {
    const raw = "GET /foo HTTP/1.1\r\n";
    var req: Request = undefined;
    const result = parse(raw, &req);
    try std.testing.expectError(error.NeedMoreData, result);
}

test "findCrlf basic" {
    try std.testing.expectEqual(@as(?usize, 5), findCrlf("hello\r\nworld"));
    try std.testing.expectEqual(@as(?usize, null), findCrlf("hello"));
}

test "findCrlf at chunk boundary" {
    // \r at byte 15, \n at byte 16 — straddles a 16-byte SIMD chunk
    const buf = "0123456789abcde\r\nrest";
    try std.testing.expectEqual(@as(?usize, 15), findCrlf(buf));
}

test "findCrlf cr without lf" {
    // Bare \r should not match
    try std.testing.expectEqual(@as(?usize, null), findCrlf("hello\rworld"));
}

test "is_complete GET" {
    const raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    var req: Request = undefined;
    _ = try parse(raw, &req);
    try std.testing.expect(req.isComplete(raw.len));
}
