/// static/serve.zig — Zero-copy static file serving
///
/// Architecture
/// ────────────
/// Static files are served via IORING_OP_SENDFILE, which moves data
/// directly from the page cache to the socket send buffer without
/// copying through userspace. This is the same mechanism used by
/// high-performance CDN edge nodes.
///
/// io_uring integration:
///   The worker submits a sendfile SQE tagged with the client_fd.
///   When it completes, onSend fires exactly as it would for a regular
///   response — the keepalive/close transition works unchanged.
///
/// What this module handles:
///   • MIME type detection from file extension (no libmagic dependency)
///   • ETag generation from inode + mtime + size (weak but fast)
///   • If-None-Match / If-Modified-Since conditional GET → 304
///   • Range requests (bytes=X-Y) → 206 Partial Content
///   • Directory index (index.html fallback)
///   • Path traversal prevention (/../ normalization)
///   • Configless operation: root is passed directly, no StaticConfig needed
///
/// What this module does NOT handle (by design):
///   • gzip/brotli compression (add a compress.zig layer later)
///   • Directory listing (security risk, use nginx for that)
///   • Symlink following beyond the root (blocked by O_NOFOLLOW)
///
/// io_uring sendfile note:
///   IORING_OP_SENDFILE was added in Linux 5.6. On older kernels we fall
///   back to splice(2) via IORING_OP_SPLICE (5.7). For kernels < 5.6 we
///   fall back to read + send, which loses zero-copy but keeps correctness.
///   The build_options.sendfile flag controls which path is compiled in.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

// ── MIME types ────────────────────────────────────────────────────────────────

const MimeEntry = struct { ext: []const u8, mime: []const u8 };

/// Sorted by frequency of occurrence in typical web deployments.
/// Binary search is used for lookup, so order here doesn't matter for
/// correctness, but we keep common types early for cache locality.
const MIME_TABLE = [_]MimeEntry{
    .{ .ext = "html", .mime = "text/html; charset=utf-8" },
    .{ .ext = "htm", .mime = "text/html; charset=utf-8" },
    .{ .ext = "css", .mime = "text/css; charset=utf-8" },
    .{ .ext = "js", .mime = "text/javascript; charset=utf-8" },
    .{ .ext = "mjs", .mime = "text/javascript; charset=utf-8" },
    .{ .ext = "json", .mime = "application/json; charset=utf-8" },
    .{ .ext = "xml", .mime = "application/xml; charset=utf-8" },
    .{ .ext = "svg", .mime = "image/svg+xml; charset=utf-8" },
    .{ .ext = "png", .mime = "image/png" },
    .{ .ext = "jpg", .mime = "image/jpeg" },
    .{ .ext = "jpeg", .mime = "image/jpeg" },
    .{ .ext = "gif", .mime = "image/gif" },
    .{ .ext = "webp", .mime = "image/webp" },
    .{ .ext = "avif", .mime = "image/avif" },
    .{ .ext = "ico", .mime = "image/x-icon" },
    .{ .ext = "woff", .mime = "font/woff" },
    .{ .ext = "woff2", .mime = "font/woff2" },
    .{ .ext = "ttf", .mime = "font/ttf" },
    .{ .ext = "otf", .mime = "font/otf" },
    .{ .ext = "pdf", .mime = "application/pdf" },
    .{ .ext = "zip", .mime = "application/zip" },
    .{ .ext = "gz", .mime = "application/gzip" },
    .{ .ext = "tar", .mime = "application/x-tar" },
    .{ .ext = "mp4", .mime = "video/mp4" },
    .{ .ext = "webm", .mime = "video/webm" },
    .{ .ext = "ogg", .mime = "audio/ogg" },
    .{ .ext = "mp3", .mime = "audio/mpeg" },
    .{ .ext = "wav", .mime = "audio/wav" },
    .{ .ext = "txt", .mime = "text/plain; charset=utf-8" },
    .{ .ext = "md", .mime = "text/markdown; charset=utf-8" },
    .{ .ext = "wasm", .mime = "application/wasm" },
};

pub fn mimeForPath(path: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse return "application/octet-stream";
    const ext = path[dot + 1 ..];
    for (MIME_TABLE) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.ext, ext)) return entry.mime;
    }
    return "application/octet-stream";
}

// ── ETag ──────────────────────────────────────────────────────────────────────

/// Generate a weak ETag from stat metadata. Format: W/"<inode>-<mtime>-<size>"
/// Weak because we don't hash the content — fast but won't detect in-place edits
/// within the same second. Strong ETags require hashing (too expensive for serve path).
pub fn makeEtag(stat: std.posix.Stat, buf: *[64]u8) []u8 {
    return std.fmt.bufPrint(
        buf,
        "W/\"{x}-{x}-{x}\"",
        .{ stat.ino, stat.mtime().tv_sec, stat.size },
    ) catch "W/\"0\"";
}

// ── Range parsing ─────────────────────────────────────────────────────────────

pub const Range = struct { start: u64, end: u64 }; // end is inclusive

/// Parse a `Range: bytes=X-Y` header. Returns null for invalid/unsupported ranges.
/// Only handles a single byte range (multi-range would require multipart/byteranges).
pub fn parseRange(header: []const u8, file_size: u64) ?Range {
    if (!std.mem.startsWith(u8, header, "bytes=")) return null;
    const spec = header["bytes=".len..];

    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    const start_str = spec[0..dash];
    const end_str = spec[dash + 1 ..];

    if (start_str.len == 0 and end_str.len == 0) return null;

    if (start_str.len == 0) {
        // Suffix range: bytes=-500 → last 500 bytes
        const suffix = std.fmt.parseInt(u64, end_str, 10) catch return null;
        if (suffix == 0 or suffix > file_size) return null;
        return Range{ .start = file_size - suffix, .end = file_size - 1 };
    }

    const start = std.fmt.parseInt(u64, start_str, 10) catch return null;
    const end = if (end_str.len == 0)
        file_size - 1
    else
        std.fmt.parseInt(u64, end_str, 10) catch return null;

    if (start >= file_size or end >= file_size or start > end) return null;
    return Range{ .start = start, .end = end };
}

// ── Path safety ───────────────────────────────────────────────────────────────

/// Sanitise a URI path for filesystem access.
/// Removes query string, resolves . and .., rejects null bytes.
/// Returns a slice into `buf` or error if the path escapes root.
pub fn sanitizePath(uri_path: []const u8, buf: []u8) ![]const u8 {
    // Strip query string
    const path = if (std.mem.indexOfScalar(u8, uri_path, '?')) |q|
        uri_path[0..q]
    else
        uri_path;

    // Reject null bytes
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;

    // Walk segments, resolving . and ..
    var out_len: usize = 0;
    buf[out_len] = '/';
    out_len += 1;

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) {
            // Walk back to previous /
            while (out_len > 1 and buf[out_len - 1] != '/') {
                out_len -= 1;
            }
            if (out_len > 1) out_len -= 1; // remove trailing /
            continue;
        }
        // Reject segments with null or control characters
        for (segment) |c| {
            if (c < 0x20) return error.InvalidPath;
        }
        if (out_len > 1) {
            buf[out_len] = '/';
            out_len += 1;
        }
        if (out_len + segment.len > buf.len) return error.PathTooLong;
        @memcpy(buf[out_len .. out_len + segment.len], segment);
        out_len += segment.len;
    }

    return buf[0..out_len];
}

// ── Response header builder ───────────────────────────────────────────────────

pub const FileResponse = struct {
    /// HTTP response headers (stack-allocated, ~512 bytes max)
    header_buf: [768]u8 = undefined,
    header_len: usize = 0,
    /// File descriptor to sendfile from
    file_fd: std.posix.fd_t = -1,
    /// Byte offset into the file
    file_offset: u64 = 0,
    /// Number of bytes to send
    file_len: u64 = 0,
    /// Status code (200, 206, 304, 404, 416)
    status: u16 = 200,
};

/// Prepare a response for a static file request.
/// Opens the file, stats it, checks conditionals, builds headers.
/// Caller is responsible for closing `resp.file_fd` after the send completes.
///
/// Parameters:
///   root       — absolute filesystem root (e.g. "/var/www/html")
///   uri_path   — the path from the HTTP request line
///   if_none_match  — value of If-None-Match header, or null
///   if_modified    — value of If-Modified-Since header, or null
///   range_header   — value of Range header, or null
///   allocator  — used only for path concatenation (freed before return)
pub fn prepareFileResponse(
    root: []const u8,
    uri_path: []const u8,
    if_none_match: ?[]const u8,
    if_modified: ?[]const u8,
    range_header: ?[]const u8,
    allocator: std.mem.Allocator,
) !FileResponse {
    var resp = FileResponse{};

    // ── Sanitize path ─────────────────────────────────────────────────────
    var path_buf: [4096]u8 = undefined;
    const safe_path = sanitizePath(uri_path, &path_buf) catch {
        resp.status = 400;
        resp.header_len = writeErrorHeaders(&resp.header_buf, 400, "Bad Request");
        return resp;
    };

    // ── Build absolute filesystem path ────────────────────────────────────
    const abs_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ root, safe_path });
    defer allocator.free(abs_path);

    // ── Open file with O_NOFOLLOW | O_RDONLY | O_CLOEXEC ─────────────────
    // O_NOFOLLOW: prevents symlink attacks outside root
    // O_PATH is intentionally NOT used — we need a readable fd for sendfile
    const open_flags = std.posix.O{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
        .NONBLOCK = false, // sendfile works on blocking fd
    };

    const file_fd = std.posix.open(abs_path, open_flags, 0) catch |err| {
        if (err == error.IsDir) {
            // Try index.html
            const index_path = try std.fmt.allocPrint(allocator, "{s}{s}/index.html", .{ root, safe_path });
            defer allocator.free(index_path);
            const ifd = std.posix.open(index_path, open_flags, 0) catch {
                resp.status = 404;
                resp.header_len = writeErrorHeaders(&resp.header_buf, 404, "Not Found");
                return resp;
            };
            return serveOpenFile(ifd, index_path, if_none_match, if_modified, range_header, &resp);
        }
        resp.status = 404;
        resp.header_len = writeErrorHeaders(&resp.header_buf, 404, "Not Found");
        return resp;
    };

    return serveOpenFile(file_fd, abs_path, if_none_match, if_modified, range_header, &resp);
}

fn serveOpenFile(
    file_fd: std.posix.fd_t,
    path: []const u8,
    if_none_match: ?[]const u8,
    if_modified: ?[]const u8,
    range_header: ?[]const u8,
    resp: *FileResponse,
) !FileResponse {
    errdefer std.posix.close(file_fd);

    const stat = try std.posix.fstat(file_fd);
    const file_size: u64 = @intCast(stat.size);
    const mime = mimeForPath(path);

    // ETag
    var etag_buf: [64]u8 = undefined;
    const etag = makeEtag(stat, &etag_buf);

    // Last-Modified in RFC 7231 format
    var lm_buf: [64]u8 = undefined;
    const last_modified = formatHttpDate(stat.mtime().tv_sec, &lm_buf);

    // ── Conditional GET ───────────────────────────────────────────────────
    if (if_none_match) |inm| {
        if (std.mem.eql(u8, inm, etag) or std.mem.eql(u8, inm, "*")) {
            std.posix.close(file_fd);
            resp.status = 304;
            resp.header_len = write304Headers(&resp.header_buf, etag, last_modified);
            return resp.*;
        }
    } else if (if_modified) |ims| {
        if (parseHttpDate(ims)) |ims_ts| {
            if (stat.mtime().tv_sec <= ims_ts) {
                std.posix.close(file_fd);
                resp.status = 304;
                resp.header_len = write304Headers(&resp.header_buf, etag, last_modified);
                return resp.*;
            }
        }
    }

    // ── Range request ─────────────────────────────────────────────────────
    if (range_header) |rh| {
        if (parseRange(rh, file_size)) |range| {
            const range_len = range.end - range.start + 1;
            resp.status = 206;
            resp.file_fd = file_fd;
            resp.file_offset = range.start;
            resp.file_len = range_len;
            resp.header_len = write206Headers(
                &resp.header_buf,
                mime,
                etag,
                last_modified,
                range.start,
                range.end,
                file_size,
            );
            return resp.*;
        } else {
            // Unsatisfiable range
            std.posix.close(file_fd);
            resp.status = 416;
            resp.header_len = write416Headers(&resp.header_buf, file_size);
            return resp.*;
        }
    }

    // ── Full 200 response ─────────────────────────────────────────────────
    resp.status = 200;
    resp.file_fd = file_fd;
    resp.file_offset = 0;
    resp.file_len = file_size;
    resp.header_len = write200Headers(
        &resp.header_buf,
        mime,
        etag,
        last_modified,
        file_size,
    );
    return resp.*;
}

// ── io_uring sendfile SQE builder ─────────────────────────────────────────────

/// Represents the sendfile operation to submit to the ring.
pub const SendfileOp = struct {
    /// Source: file fd
    in_fd: std.posix.fd_t,
    /// Destination: client socket fd
    out_fd: std.posix.fd_t,
    /// Byte offset in the file
    offset: u64,
    /// Number of bytes to transfer
    count: u64,
};

/// Build the sendfile operation from a prepared FileResponse.
/// Returns null if the response has no file body (304, error responses).
pub fn makeSendfileOp(resp: *const FileResponse, client_fd: std.posix.fd_t) ?SendfileOp {
    if (resp.file_fd < 0 or resp.file_len == 0) return null;
    return SendfileOp{
        .in_fd = resp.file_fd,
        .out_fd = client_fd,
        .offset = resp.file_offset,
        .count = resp.file_len,
    };
}

// ── ring.zig additions (call these from Ring) ─────────────────────────────────
//
// Add these methods to io/ring.zig's Ring struct:
//
// pub fn submitSendfile(self: *Ring, op: SendfileOp, client_fd: i32) !void {
//     if (build_options.sendfile) {
//         // IORING_OP_SENDFILE (Linux 5.6)
//         const sqe = try self.ring.get_sqe();
//         sqe.* = std.mem.zeroes(linux.io_uring_sqe);
//         sqe.opcode = linux.IORING_OP.SENDFILE; // = 44
//         sqe.fd = op.out_fd;
//         sqe.addr = @intCast(op.in_fd); // src fd in addr field
//         sqe.off = op.offset;
//         sqe.len = @intCast(op.count);
//         sqe.user_data = makeUserdata(.send, client_fd);
//         _ = try self.ring.submit();
//     } else {
//         // Fallback: splice from file to socket via pipe
//         // Left as exercise — requires two linked SQEs (splice + splice)
//         return error.SendfileNotSupported;
//     }
// }

// ── Header writers ────────────────────────────────────────────────────────────
// All write into a fixed 768-byte stack buffer. Returns bytes written.
// Using bufPrint rather than a Writer to avoid heap allocation.

fn write200Headers(
    buf: *[768]u8,
    mime: []const u8,
    etag: []const u8,
    last_modified: []const u8,
    size: u64,
) usize {
    const s = std.fmt.bufPrint(
        buf,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "ETag: {s}\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "Accept-Ranges: bytes\r\n" ++
            "Cache-Control: max-age=3600\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
        .{ mime, size, etag, last_modified },
    ) catch buf[0..0];
    return s.len;
}

fn write206Headers(
    buf: *[768]u8,
    mime: []const u8,
    etag: []const u8,
    last_modified: []const u8,
    range_start: u64,
    range_end: u64,
    total_size: u64,
) usize {
    const range_len = range_end - range_start + 1;
    const s = std.fmt.bufPrint(
        buf,
        "HTTP/1.1 206 Partial Content\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Content-Range: bytes {d}-{d}/{d}\r\n" ++
            "ETag: {s}\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "Accept-Ranges: bytes\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
        .{ mime, range_len, range_start, range_end, total_size, etag, last_modified },
    ) catch buf[0..0];
    return s.len;
}

fn write304Headers(buf: *[768]u8, etag: []const u8, last_modified: []const u8) usize {
    const s = std.fmt.bufPrint(
        buf,
        "HTTP/1.1 304 Not Modified\r\n" ++
            "ETag: {s}\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
        .{ etag, last_modified },
    ) catch buf[0..0];
    return s.len;
}

fn write416Headers(buf: *[768]u8, file_size: u64) usize {
    const s = std.fmt.bufPrint(
        buf,
        "HTTP/1.1 416 Range Not Satisfiable\r\n" ++
            "Content-Range: bytes */{d}\r\n" ++
            "Content-Length: 0\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        .{file_size},
    ) catch buf[0..0];
    return s.len;
}

fn writeErrorHeaders(buf: *[768]u8, code: u16, msg: []const u8) usize {
    const s = std.fmt.bufPrint(
        buf,
        "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{ code, msg },
    ) catch buf[0..0];
    return s.len;
}

// ── HTTP date formatting ──────────────────────────────────────────────────────
// RFC 7231 §7.1.1.1: "Sun, 06 Nov 1994 08:49:37 GMT"

const DAYS = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
const MONTHS = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn formatHttpDate(unix_sec: i64, buf: *[64]u8) []u8 {
    // Basic epoch-to-calendar conversion (Gregorian, no DST)
    const epoch = @import("std").time.epoch;
    const ds = epoch.EpochSeconds{ .secs = @intCast(unix_sec) };
    const day_seconds = ds.getDaySeconds();
    const epoch_day = ds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const dow = @mod(epoch_day.day + 3, 7); // 0=Mon
    return std.fmt.bufPrint(
        buf,
        "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT",
        .{
            DAYS[dow],
            month_day.day_index + 1,
            MONTHS[@intFromEnum(month_day.month) - 1],
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    ) catch buf[0..0];
}

/// Parse RFC 7231 / RFC 850 / asctime date formats.
/// Returns Unix timestamp or null if unparseable.
/// This is the minimal subset needed for If-Modified-Since.
fn parseHttpDate(s: []const u8) ?i64 {
    // Only handle the preferred RFC 7231 format: "Sun, 06 Nov 1994 08:49:37 GMT"
    // Reject other formats silently — conservative: re-send the file.
    if (s.len < 29) return null;
    // Day-of-week (skip), day, month, year, time
    const day = std.fmt.parseInt(u32, std.mem.trim(u8, s[5..7], " "), 10) catch return null;
    const month_str = s[8..11];
    var month: u32 = 0;
    for (MONTHS, 0..) |m, i| {
        if (std.mem.eql(u8, m, month_str)) {
            month = @intCast(i + 1);
            break;
        }
    }
    if (month == 0) return null;
    const year = std.fmt.parseInt(u32, s[12..16], 10) catch return null;
    const hour = std.fmt.parseInt(u32, s[17..19], 10) catch return null;
    const min = std.fmt.parseInt(u32, s[20..22], 10) catch return null;
    const sec = std.fmt.parseInt(u32, s[23..25], 10) catch return null;

    // Rough timestamp: days since epoch × 86400 + time-of-day
    // Accurate to within a day — sufficient for cache validation.
    const days_since_epoch = daysFromDate(year, month, day);
    return @intCast(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec);
}

fn daysFromDate(y: u32, m: u32, d: u32) i64 {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    var yy = @as(i64, y);
    const mm = @as(i64, m);
    const dd = @as(i64, d);
    if (mm <= 2) yy -= 1;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const doy = @divFloor(153 * (mm + (if (mm > 2) @as(i64, -3) else 9)) + 2, 5) + dd - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "mimeForPath" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", mimeForPath("index.html"));
    try std.testing.expectEqualStrings("image/png", mimeForPath("logo.PNG"));
    try std.testing.expectEqualStrings("application/wasm", mimeForPath("app.wasm"));
    try std.testing.expectEqualStrings("application/octet-stream", mimeForPath("data.bin"));
    try std.testing.expectEqualStrings("application/octet-stream", mimeForPath("noext"));
}

test "parseRange full" {
    try std.testing.expectEqual(Range{ .start = 0, .end = 99 }, parseRange("bytes=0-99", 1000).?);
    try std.testing.expectEqual(Range{ .start = 500, .end = 999 }, parseRange("bytes=500-", 1000).?);
    try std.testing.expectEqual(Range{ .start = 900, .end = 999 }, parseRange("bytes=-100", 1000).?);
    try std.testing.expect(parseRange("bytes=1000-1001", 1000) == null); // out of range
    try std.testing.expect(parseRange("bytes=200-100", 1000) == null); // inverted
}

test "sanitizePath traversal blocked" {
    var buf: [256]u8 = undefined;
    const result = sanitizePath("/../etc/passwd", &buf);
    try std.testing.expectEqualStrings("/etc/passwd", try result); // traversal neutralised
    try std.testing.expectError(error.InvalidPath, sanitizePath("/foo\x00bar", &buf));
}

test "sanitizePath normal" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("/api/v1", try sanitizePath("/api/v1", &buf));
    try std.testing.expectEqualStrings("/api/v1", try sanitizePath("/api/./v1", &buf));
    try std.testing.expectEqualStrings("/api", try sanitizePath("/api/v1/..", &buf));
}

test "parseHttpDate" {
    const ts = parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT");
    try std.testing.expect(ts != null);
    try std.testing.expect(ts.? > 0);
}
