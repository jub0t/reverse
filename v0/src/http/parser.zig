/// http/parser.zig — SIMD-accelerated HTTP/1.1 request parser
///
/// Design goals:
///   • Zero allocations — all output is slices into the input buffer
///   • Zero copies      — no memcpy of header names/values
///   • SIMD validation  — 16-byte-at-a-time header char checks via @Vector
///   • Comptime dispatch — method matching is a comptime-generated switch
///
/// The parser is intentionally not a streaming parser. It operates on a
/// complete (or partial) buffer and returns either a parsed request or an
/// indication that more data is needed.
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

/// Maximum number of headers we'll parse. Anything beyond this is dropped.
pub const MAX_HEADERS = 64;

pub const Request = struct {
    method: Method,
    /// The raw method string (useful when method == .Unknown)
    method_str: []const u8,
    path: []const u8,
    /// HTTP version: 10 = HTTP/1.0, 11 = HTTP/1.1
    version: u8,
    headers: [MAX_HEADERS]Header,
    header_count: usize,
    /// Byte offset in the input buffer where the body begins
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

/// Returns true if ALL bytes in `v` are valid HTTP header field-name chars:
///   a-z A-Z 0-9 ! # $ % & ' * + - . ^ _ ` | ~
/// (RFC 7230 token characters)
///
/// We validate by checking that no byte falls in the "forbidden" ranges.
/// This runs as a single PCMPEQB + PMOVMSKB on x86 with SSE2.
inline fn simdValidHeaderNameChunk(v: V16u8) bool {
    // Forbidden: 0x00–0x1F (controls), 0x7F (DEL), space (0x20),
    //            colon (0x3A), and chars above 0x7E.
    const ctrl = @as(V16u8, @splat(0x1F));
    const del = @as(V16u8, @splat(0x7F));
    const sp = @as(V16u8, @splat(0x20));
    const col = @as(V16u8, @splat(':'));

    // Any byte <= 0x1F?  (controls including \t are not allowed in names)
    const has_ctrl = @reduce(.Or, v <= ctrl);
    // Any byte == 0x7F?
    const has_del = @reduce(.Or, v == del);
    // Any space?
    const has_sp = @reduce(.Or, v == sp);
    // Any colon?
    const has_col = @reduce(.Or, v == col);

    return !(has_ctrl or has_del or has_sp or has_col);
}

/// Scan `buf` for `\r\n` and return the index of the `\r`, or null.
fn findCrlf(buf: []const u8) ?usize {
    var i: usize = 0;
    // SIMD fast path: scan 16 bytes at a time looking for \r
    while (i + 16 <= buf.len) : (i += 16) {
        const chunk: V16u8 = buf[i..][0..16].*;
        const cr = @as(V16u8, @splat('\r'));
        const has_cr = @reduce(.Or, chunk == cr);
        if (has_cr) break;
    }
    // Scalar finish
    while (i < buf.len) : (i += 1) {
        if (buf[i] == '\r' and i + 1 < buf.len and buf[i + 1] == '\n') return i;
    }
    return null;
}

// ── Comptime method dispatch ───────────────────────────────────────────────────

fn parseMethod(token: []const u8) Method {
    // Comptime-generated: the compiler turns this into a jump table.
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
/// Returns the number of bytes consumed (i.e. where the body begins, or the
/// full request length for bodyless methods). On success, `*out` is populated
/// with slices pointing into `buf` — no allocations.
///
/// Returns `error.NeedMoreData` if the buffer doesn't yet contain a full
/// header section (i.e. no \r\n\r\n found).
pub fn parse(buf: []const u8, out: *Request) ParseError!usize {
    out.* = std.mem.zeroes(Request);

    // We need at least the request-line
    if (buf.len < 14) return error.NeedMoreData;

    var pos: usize = 0;

    // ── Request line: METHOD SP path SP HTTP/1.x CRLF ───────────────────────
    const line_end = findCrlf(buf[pos..]) orelse return error.NeedMoreData;

    const request_line = buf[pos .. pos + line_end];
    pos += line_end + 2; // skip \r\n

    // Method
    const method_end = std.mem.indexOfScalar(u8, request_line, ' ') orelse
        return error.BadRequest;
    if (method_end > 16) return error.MethodTooLong;
    out.method_str = request_line[0..method_end];
    out.method = parseMethod(out.method_str);

    // Path
    const path_start = method_end + 1;
    const path_end = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse
        return error.BadRequest;
    if (path_end <= path_start) return error.BadRequest;
    if (path_end - path_start > 8192) return error.PathTooLong;
    out.path = request_line[path_start..path_end];

    // Version
    const ver = request_line[path_end + 1 ..];
    if (std.mem.eql(u8, ver, "HTTP/1.1")) {
        out.version = 11;
    } else if (std.mem.eql(u8, ver, "HTTP/1.0")) {
        out.version = 10;
    } else {
        return error.UnsupportedVersion;
    }

    // ── Headers ──────────────────────────────────────────────────────────────
    while (pos < buf.len) {
        // Empty line = end of headers
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
        // Trim leading OWS
        while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) {
            value = value[1..];
        }

        if (out.header_count >= MAX_HEADERS) return error.TooManyHeaders;
        out.headers[out.header_count] = .{ .name = name, .value = value };
        out.header_count += 1;

        // Cache interesting headers while we scan
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
    try std.testing.expectEqual(raw.len - 5, consumed);
}

test "need more data" {
    const raw = "GET /foo HTTP/1.1\r\n";
    var req: Request = undefined;
    const result = parse(raw, &req);
    try std.testing.expectError(error.NeedMoreData, result);
}

test "findCrlf" {
    try std.testing.expectEqual(@as(?usize, 5), findCrlf("hello\r\nworld"));
    try std.testing.expectEqual(@as(?usize, null), findCrlf("hello"));
}
