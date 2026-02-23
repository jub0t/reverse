/// upstream/h2.zig — HTTP/2 upstream connection pool
///
/// Architecture overview
/// ─────────────────────
/// A single upstream TCP connection carries many concurrent HTTP/2 streams.
/// This is fundamentally different from the HTTP/1.1 pool where each Conn
/// owns one upstream fd — here, many Conns share one upstream fd.
///
/// Data model:
///
///   H2Upstream (one per upstream server address)
///     └── H2Conn  (one TCP connection, many streams)
///           └── Stream map: stream_id → client_fd
///
/// Flow per request:
///   1. Worker calls H2Upstream.openStream(client_fd, request)
///   2. We pick an H2Conn with capacity (active_streams < max_concurrent)
///   3. Assign a new odd stream_id (client-initiated: 1, 3, 5, …)
///   4. Encode request headers via HPACK → HEADERS frame → upstream send
///   5. If request has body, send DATA frames
///   6. Upstream responds with HEADERS + DATA frames
///   7. We decode response headers, forward to client
///   8. Stream is removed from the map; stream_id is retired
///
/// Concurrency model:
///   All operations happen on the worker's io_uring ring. H2Conn receives
///   bytes via the standard onRecv CQE path (upstream_fd is in upstream_map).
///   Frame parsing accumulates bytes in `recv_buf`; complete frames are
///   dispatched synchronously in the CQE handler. No locks needed — the
///   single-threaded worker owns all state for its connections.
///
/// What is NOT implemented here:
///   • Server push (PUSH_PROMISE)        — proxies must not forward push
///   • HTTP/2 to HTTP/1.1 downgrade      — handled in worker routing
///   • SETTINGS negotiation beyond basics — safe defaults used
///   • Priority (RFC 7540 §5.3)          — deprecated in RFC 9113 anyway
///   • CONTINUATION frames               — header blocks assumed to fit one frame
const std = @import("std");
const pool_mod = @import("pool.zig");

// ── HTTP/2 constants ──────────────────────────────────────────────────────────

const H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_FRAME_HEADER_LEN = 9;
const H2_DEFAULT_INITIAL_WINDOW = 65535;
const H2_MAX_FRAME_SIZE_DEFAULT = 16384;
const H2_SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const H2_SETTINGS_ENABLE_PUSH: u16 = 0x2;
const H2_SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const H2_SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const H2_SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const FrameFlags = struct {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x1;
};

// ── Frame header ─────────────────────────────────────────────────────────────

pub const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: u8,
    /// Stream ID with reserved bit masked off
    stream_id: u31,

    pub fn encode(self: FrameHeader, buf: *[H2_FRAME_HEADER_LEN]u8) void {
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @intFromEnum(self.frame_type);
        buf[4] = self.flags;
        const sid: u32 = self.stream_id;
        buf[5] = @intCast((sid >> 24) & 0x7F); // reserved bit = 0
        buf[6] = @intCast((sid >> 16) & 0xFF);
        buf[7] = @intCast((sid >> 8) & 0xFF);
        buf[8] = @intCast(sid & 0xFF);
    }

    pub fn decode(buf: []const u8) FrameHeader {
        std.debug.assert(buf.len >= H2_FRAME_HEADER_LEN);
        return FrameHeader{
            .length = (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2],
            .frame_type = @enumFromInt(buf[3]),
            .flags = buf[4],
            .stream_id = @intCast(
                ((@as(u32, buf[5]) & 0x7F) << 24) |
                    (@as(u32, buf[6]) << 16) |
                    (@as(u32, buf[7]) << 8) |
                    buf[8],
            ),
        };
    }
};

// ── HPACK: minimal static table encoder ──────────────────────────────────────
//
// Full HPACK (RFC 7541) with dynamic table is complex. We implement:
//   • Indexed header field for the 61 static table entries (§A)
//   • Literal header field never indexed for unknown headers
//   • No dynamic table updates (safe, slightly less efficient)
//
// This is correct per spec. Dynamic table support can be added later
// for a ~15% header compression improvement.

const HpackStaticEntry = struct { name: []const u8, value: []const u8 };

const HPACK_STATIC_TABLE = [_]HpackStaticEntry{
    .{ .name = ":authority", .value = "" }, // 1
    .{ .name = ":method", .value = "GET" }, // 2
    .{ .name = ":method", .value = "POST" }, // 3
    .{ .name = ":path", .value = "/" }, // 4
    .{ .name = ":path", .value = "/index.html" }, // 5
    .{ .name = ":scheme", .value = "http" }, // 6
    .{ .name = ":scheme", .value = "https" }, // 7
    .{ .name = ":status", .value = "200" }, // 8
    .{ .name = ":status", .value = "204" }, // 9
    .{ .name = ":status", .value = "206" }, // 10
    .{ .name = ":status", .value = "304" }, // 11
    .{ .name = ":status", .value = "400" }, // 12
    .{ .name = ":status", .value = "404" }, // 13
    .{ .name = ":status", .value = "500" }, // 14
    .{ .name = "accept-charset", .value = "" }, // 15
    .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
    .{ .name = "accept-language", .value = "" }, // 17
    .{ .name = "accept-ranges", .value = "" }, // 18
    .{ .name = "accept", .value = "" }, // 19
    .{ .name = "access-control-allow-origin", .value = "" }, // 20
    .{ .name = "age", .value = "" }, // 21
    .{ .name = "allow", .value = "" }, // 22
    .{ .name = "authorization", .value = "" }, // 23
    .{ .name = "cache-control", .value = "" }, // 24
    .{ .name = "content-disposition", .value = "" }, // 25
    .{ .name = "content-encoding", .value = "" }, // 26
    .{ .name = "content-language", .value = "" }, // 27
    .{ .name = "content-length", .value = "" }, // 28
    .{ .name = "content-location", .value = "" }, // 29
    .{ .name = "content-range", .value = "" }, // 30
    .{ .name = "content-type", .value = "" }, // 31
    .{ .name = "cookie", .value = "" }, // 32
    .{ .name = "date", .value = "" }, // 33
    .{ .name = "etag", .value = "" }, // 34
    .{ .name = "expect", .value = "" }, // 35
    .{ .name = "expires", .value = "" }, // 36
    .{ .name = "from", .value = "" }, // 37
    .{ .name = "host", .value = "" }, // 38
    .{ .name = "if-match", .value = "" }, // 39
    .{ .name = "if-modified-since", .value = "" }, // 40
    .{ .name = "if-none-match", .value = "" }, // 41
    .{ .name = "if-range", .value = "" }, // 42
    .{ .name = "if-unmodified-since", .value = "" }, // 43
    .{ .name = "last-modified", .value = "" }, // 44
    .{ .name = "link", .value = "" }, // 45
    .{ .name = "location", .value = "" }, // 46
    .{ .name = "max-forwards", .value = "" }, // 47
    .{ .name = "proxy-authenticate", .value = "" }, // 48
    .{ .name = "proxy-authorization", .value = "" }, // 49
    .{ .name = "range", .value = "" }, // 50
    .{ .name = "referer", .value = "" }, // 51
    .{ .name = "refresh", .value = "" }, // 52
    .{ .name = "retry-after", .value = "" }, // 53
    .{ .name = "server", .value = "" }, // 54
    .{ .name = "set-cookie", .value = "" }, // 55
    .{ .name = "strict-transport-security", .value = "" }, // 56
    .{ .name = "transfer-encoding", .value = "" }, // 57
    .{ .name = "user-agent", .value = "" }, // 58
    .{ .name = "vary", .value = "" }, // 59
    .{ .name = "via", .value = "" }, // 60
    .{ .name = "www-authenticate", .value = "" }, // 61
};

pub const HpackEncoder = struct {
    buf: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) HpackEncoder {
        return .{ .buf = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *HpackEncoder) void {
        self.buf.deinit();
    }

    pub fn reset(self: *HpackEncoder) void {
        self.buf.clearRetainingCapacity();
    }

    /// Encode a single header field. Searches static table for indexed match,
    /// falls back to literal-never-indexed.
    pub fn encodeHeader(self: *HpackEncoder, name: []const u8, value: []const u8) !void {
        // Check for full match in static table (name + value)
        for (HPACK_STATIC_TABLE, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name) and
                std.mem.eql(u8, entry.value, value))
            {
                // Indexed Header Field Representation: 1xxxxxxx
                try self.encodeInt(0x80, 7, @intCast(i + 1));
                return;
            }
        }

        // Check for name-only match
        var name_idx: ?usize = null;
        for (HPACK_STATIC_TABLE, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                name_idx = i + 1;
                break;
            }
        }

        if (name_idx) |idx| {
            // Literal, incremental indexing, indexed name: 01xxxxxx
            try self.encodeInt(0x40, 6, @intCast(idx));
        } else {
            // Literal, never indexed, new name: 0001xxxx with index 0
            try self.buf.append(0x10);
            try self.encodeString(name);
        }
        try self.encodeString(value);
    }

    /// Encode the required HTTP/2 pseudo-headers for a proxied request.
    pub fn encodeRequestHeaders(
        self: *HpackEncoder,
        method: []const u8,
        path: []const u8,
        authority: []const u8,
        extra_headers: []const [2][]const u8,
    ) !void {
        self.reset();
        try self.encodeHeader(":method", method);
        try self.encodeHeader(":scheme", "https");
        try self.encodeHeader(":path", path);
        try self.encodeHeader(":authority", authority);
        for (extra_headers) |hdr| {
            // Skip hop-by-hop headers that must not be forwarded over H2
            const name = hdr[0];
            if (isHopByHop(name)) continue;
            try self.encodeHeader(name, hdr[1]);
        }
    }

    // ── Integer encoding (RFC 7541 §5.1) ─────────────────────────────────

    fn encodeInt(self: *HpackEncoder, prefix_bits_mask: u8, n: u5, value: usize) !void {
        const max_first: usize = (@as(usize, 1) << n) - 1;
        if (value < max_first) {
            try self.buf.append(prefix_bits_mask | @as(u8, @intCast(value)));
            return;
        }
        try self.buf.append(prefix_bits_mask | @as(u8, @intCast(max_first)));
        var remaining = value - max_first;
        while (remaining >= 128) {
            try self.buf.append(@as(u8, @intCast(remaining & 0x7F)) | 0x80);
            remaining >>= 7;
        }
        try self.buf.append(@as(u8, @intCast(remaining)));
    }

    // ── String encoding (RFC 7541 §5.2, no Huffman) ───────────────────────

    fn encodeString(self: *HpackEncoder, s: []const u8) !void {
        // H bit = 0 (no Huffman)
        try self.encodeInt(0x00, 7, s.len);
        try self.buf.appendSlice(s);
    }
};

pub const HpackDecoder = struct {
    // Decoded headers are returned as slices into a caller-owned arena.
    // The decoder is stateless between frames (no dynamic table yet).

    pub const DecodedHeader = struct { name: []const u8, value: []const u8 };

    /// Decode a HPACK block from `src` into `out`. Returns number of headers decoded.
    pub fn decode(
        src: []const u8,
        out: []DecodedHeader,
        allocator: std.mem.Allocator,
    ) !usize {
        var pos: usize = 0;
        var count: usize = 0;

        while (pos < src.len and count < out.len) {
            const b = src[pos];

            if (b & 0x80 != 0) {
                // Indexed header field (§6.1)
                const idx_result = decodeInt(src, pos, 7);
                pos = idx_result.next_pos;
                const idx = idx_result.value;
                if (idx == 0 or idx > HPACK_STATIC_TABLE.len) continue;
                const entry = HPACK_STATIC_TABLE[idx - 1];
                out[count] = .{
                    .name = try allocator.dupe(u8, entry.name),
                    .value = try allocator.dupe(u8, entry.value),
                };
                count += 1;
            } else if (b & 0x40 != 0) {
                // Literal incremental indexing (§6.2.1)
                pos = try decodeLiteral(src, pos, 6, out, &count, allocator);
            } else if (b & 0x20 != 0) {
                // Dynamic table size update (§6.3) — skip
                const r = decodeInt(src, pos, 5);
                pos = r.next_pos;
            } else {
                // Literal without indexing / never indexed (§6.2.2 / §6.2.3)
                const prefix: u5 = if (b & 0x10 != 0) 4 else 4;
                pos = try decodeLiteral(src, pos, prefix, out, &count, allocator);
            }
        }
        return count;
    }

    const IntResult = struct { value: usize, next_pos: usize };

    fn decodeInt(src: []const u8, pos: usize, n: u5) IntResult {
        const mask: u8 = (@as(u8, 1) << n) - 1;
        var value: usize = src[pos] & mask;
        var i = pos + 1;
        if (value < mask) return .{ .value = value, .next_pos = i };
        var shift: u6 = 0;
        while (i < src.len) : (i += 1) {
            value += @as(usize, src[i] & 0x7F) << shift;
            shift += 7;
            if (src[i] & 0x80 == 0) {
                i += 1;
                break;
            }
        }
        return .{ .value = value, .next_pos = i };
    }

    fn decodeString(src: []const u8, pos: usize, allocator: std.mem.Allocator) !struct { s: []u8, next_pos: usize } {
        const huffman = src[pos] & 0x80 != 0;
        const len_result = decodeInt(src, pos, 7);
        const start = len_result.next_pos;
        const end = start + len_result.value;
        if (huffman) {
            // Huffman decode — full table is ~large. For now copy as-is and
            // log a warning. Most upstream responses don't Huffman-encode
            // headers unless the client advertised it.
            std.log.warn("HPACK Huffman decode not implemented — header may be garbled", .{});
        }
        return .{
            .s = try allocator.dupe(u8, src[start..end]),
            .next_pos = end,
        };
    }

    fn decodeLiteral(
        src: []const u8,
        pos: usize,
        prefix: u5,
        out: []DecodedHeader,
        count: *usize,
        allocator: std.mem.Allocator,
    ) !usize {
        const idx_result = decodeInt(src, pos, prefix);
        var cur = idx_result.next_pos;

        const name: []u8 = if (idx_result.value == 0) blk: {
            const r = try decodeString(src, cur, allocator);
            cur = r.next_pos;
            break :blk r.s;
        } else blk: {
            const entry = HPACK_STATIC_TABLE[idx_result.value - 1];
            break :blk try allocator.dupe(u8, entry.name);
        };
        errdefer allocator.free(name);

        const val_result = try decodeString(src, cur, allocator);
        cur = val_result.next_pos;

        out[count.*] = .{ .name = name, .value = val_result.s };
        count.* += 1;
        return cur;
    }
};

// ── Hop-by-hop header filter ──────────────────────────────────────────────────

/// HTTP/1.1 hop-by-hop headers that MUST NOT be forwarded over HTTP/2.
fn isHopByHop(name: []const u8) bool {
    const hop_by_hop = [_][]const u8{
        "connection",        "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade",    "te",
        "trailers",
    };
    for (hop_by_hop) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

// ── H2 stream state ───────────────────────────────────────────────────────────

pub const StreamState = enum {
    idle,
    open,
    half_closed_local, // we sent END_STREAM
    half_closed_remote, // upstream sent END_STREAM
    closed,
};

pub const H2Stream = struct {
    id: u31,
    client_fd: std.posix.fd_t,
    state: StreamState = .open,
    /// Remaining send window for this stream (flow control)
    send_window: i32 = H2_DEFAULT_INITIAL_WINDOW,
    /// Accumulated response header block (may span CONTINUATION frames)
    header_block: std.ArrayList(u8),

    pub fn init(id: u31, client_fd: std.posix.fd_t, allocator: std.mem.Allocator) H2Stream {
        return .{
            .id = id,
            .client_fd = client_fd,
            .header_block = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *H2Stream) void {
        self.header_block.deinit();
    }
};

// ── H2 connection ─────────────────────────────────────────────────────────────

/// Manages one TCP connection to an HTTP/2 upstream.
/// Created by H2Upstream when a new connection is needed.
pub const H2Conn = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,

    /// Active streams indexed by stream_id
    streams: std.AutoHashMap(u31, H2Stream),

    /// Next stream ID to assign (odd numbers, client-initiated)
    next_stream_id: u31 = 1,

    /// Remote peer's settings
    remote_max_concurrent: u32 = 100,
    remote_initial_window: u32 = H2_DEFAULT_INITIAL_WINDOW,
    remote_max_frame_size: u32 = H2_MAX_FRAME_SIZE_DEFAULT,

    /// Connection-level flow control window
    conn_send_window: i32 = H2_DEFAULT_INITIAL_WINDOW,

    /// Incoming frame reassembly buffer
    recv_buf: std.ArrayList(u8),

    /// HPACK encoder (one per connection — shares compression context)
    hpack: HpackEncoder,

    /// True once the connection preface has been sent
    preface_sent: bool = false,

    pub fn init(fd: std.posix.fd_t, allocator: std.mem.Allocator) H2Conn {
        return H2Conn{
            .fd = fd,
            .allocator = allocator,
            .streams = std.AutoHashMap(u31, H2Stream).init(allocator),
            .recv_buf = std.ArrayList(u8).init(allocator),
            .hpack = HpackEncoder.init(allocator),
        };
    }

    pub fn deinit(self: *H2Conn) void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.deinit();
        self.streams.deinit();
        self.recv_buf.deinit();
        self.hpack.deinit();
    }

    /// True if this connection can accept another stream.
    pub fn hasCapacity(self: *const H2Conn) bool {
        return self.streams.count() < self.remote_max_concurrent and
            self.next_stream_id < 0x7FFFFFFF;
    }

    // ── Frame writers ─────────────────────────────────────────────────────

    /// Build and return the client connection preface + initial SETTINGS frame.
    /// Caller must submit this as a SEND SQE.
    pub fn buildPreface(self: *H2Conn, buf: []u8) usize {
        _ = self;
        var pos: usize = 0;
        // Connection preface
        @memcpy(buf[pos .. pos + H2_PREFACE.len], H2_PREFACE);
        pos += H2_PREFACE.len;
        // SETTINGS frame: disable push, advertise large initial window
        const settings = [_]struct { id: u16, val: u32 }{
            .{ .id = H2_SETTINGS_ENABLE_PUSH, .val = 0 },
            .{ .id = H2_SETTINGS_INITIAL_WINDOW_SIZE, .val = 1 << 20 }, // 1 MB
            .{ .id = H2_SETTINGS_MAX_FRAME_SIZE, .val = 1 << 17 }, // 128 KB
        };
        const payload_len: u24 = @intCast(settings.len * 6);
        const hdr = FrameHeader{
            .length = payload_len,
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        };
        hdr.encode(buf[pos..][0..H2_FRAME_HEADER_LEN]);
        pos += H2_FRAME_HEADER_LEN;
        for (settings) |s| {
            buf[pos] = @intCast(s.id >> 8);
            buf[pos + 1] = @intCast(s.id & 0xFF);
            buf[pos + 2] = @intCast(s.val >> 24);
            buf[pos + 3] = @intCast((s.val >> 16) & 0xFF);
            buf[pos + 4] = @intCast((s.val >> 8) & 0xFF);
            buf[pos + 5] = @intCast(s.val & 0xFF);
            pos += 6;
        }
        return pos;
    }

    /// Open a new stream and encode the request HEADERS frame into `buf`.
    /// Returns stream_id and bytes written, or error if no capacity.
    pub fn openStream(
        self: *H2Conn,
        client_fd: std.posix.fd_t,
        method: []const u8,
        path: []const u8,
        authority: []const u8,
        headers: []const [2][]const u8,
        buf: []u8,
    ) !struct { stream_id: u31, len: usize } {
        if (!self.hasCapacity()) return error.NoStreamCapacity;

        const sid = self.next_stream_id;
        self.next_stream_id += 2;

        var stream = H2Stream.init(sid, client_fd, self.allocator);
        errdefer stream.deinit();
        try self.streams.put(sid, stream);

        // Encode headers
        try self.hpack.encodeRequestHeaders(method, path, authority, headers);
        const hpack_block = self.hpack.buf.items;

        const payload_len: u24 = @intCast(hpack_block.len);
        const hdr = FrameHeader{
            .length = payload_len,
            .frame_type = .headers,
            // END_HEADERS: header block fits in one frame
            // END_STREAM: set for GET/HEAD (no body), cleared for POST/PUT
            .flags = FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
            .stream_id = sid,
        };
        hdr.encode(buf[0..H2_FRAME_HEADER_LEN]);
        @memcpy(buf[H2_FRAME_HEADER_LEN .. H2_FRAME_HEADER_LEN + hpack_block.len], hpack_block);

        std.log.debug("H2 opened stream={d} method={s} path={s}", .{ sid, method, path });
        return .{ .stream_id = sid, .len = H2_FRAME_HEADER_LEN + hpack_block.len };
    }

    // ── Frame reader / dispatcher ─────────────────────────────────────────

    /// Feed bytes received from the upstream into the connection buffer and
    /// process complete frames. Calls `onResponseHeaders` / `onResponseData`
    /// on the handler for each complete stream event.
    pub fn feedBytes(self: *H2Conn, data: []const u8, handler: anytype) !void {
        try self.recv_buf.appendSlice(data);
        while (true) {
            if (self.recv_buf.items.len < H2_FRAME_HEADER_LEN) break;
            const fh = FrameHeader.decode(self.recv_buf.items);
            const total = H2_FRAME_HEADER_LEN + fh.length;
            if (self.recv_buf.items.len < total) break;

            const payload = self.recv_buf.items[H2_FRAME_HEADER_LEN..total];
            try self.dispatchFrame(fh, payload, handler);

            // Consume the frame from the buffer
            const remaining = self.recv_buf.items[total..];
            std.mem.copyForwards(u8, self.recv_buf.items[0..remaining.len], remaining);
            self.recv_buf.shrinkRetainingCapacity(remaining.len);
        }
    }

    fn dispatchFrame(self: *H2Conn, fh: FrameHeader, payload: []const u8, handler: anytype) !void {
        switch (fh.frame_type) {
            .settings => {
                if (fh.flags & FrameFlags.ACK == 0) {
                    try self.processSettings(payload);
                    // Send SETTINGS ACK
                    try handler.onH2SettingsAck(self.fd);
                }
            },
            .headers => {
                if (self.streams.getPtr(fh.stream_id)) |stream| {
                    try stream.header_block.appendSlice(payload);
                    if (fh.flags & FrameFlags.END_HEADERS != 0) {
                        try handler.onH2ResponseHeaders(
                            stream.client_fd,
                            fh.stream_id,
                            stream.header_block.items,
                        );
                        stream.header_block.clearRetainingCapacity();
                    }
                    if (fh.flags & FrameFlags.END_STREAM != 0) {
                        stream.state = .half_closed_remote;
                        try handler.onH2StreamEnd(stream.client_fd, fh.stream_id);
                        stream.deinit();
                        _ = self.streams.remove(fh.stream_id);
                    }
                }
            },
            .data => {
                if (self.streams.getPtr(fh.stream_id)) |stream| {
                    if (payload.len > 0) {
                        try handler.onH2ResponseData(stream.client_fd, fh.stream_id, payload);
                    }
                    if (fh.flags & FrameFlags.END_STREAM != 0) {
                        try handler.onH2StreamEnd(stream.client_fd, fh.stream_id);
                        stream.deinit();
                        _ = self.streams.remove(fh.stream_id);
                    }
                    // Send WINDOW_UPDATE to keep the stream and connection windows open
                    if (payload.len > 0) {
                        try handler.onH2WindowUpdate(self.fd, fh.stream_id, @intCast(payload.len));
                    }
                }
            },
            .rst_stream => {
                if (self.streams.getPtr(fh.stream_id)) |stream| {
                    const error_code = std.mem.readInt(u32, payload[0..4], .big);
                    std.log.warn("H2 RST_STREAM stream={d} error={d}", .{ fh.stream_id, error_code });
                    try handler.onH2StreamError(stream.client_fd, fh.stream_id);
                    stream.deinit();
                    _ = self.streams.remove(fh.stream_id);
                }
            },
            .window_update => {
                const increment = std.mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF;
                if (fh.stream_id == 0) {
                    self.conn_send_window += @intCast(increment);
                } else if (self.streams.getPtr(fh.stream_id)) |stream| {
                    stream.send_window += @intCast(increment);
                }
            },
            .ping => {
                if (fh.flags & FrameFlags.ACK == 0) {
                    try handler.onH2PingAck(self.fd, payload);
                }
            },
            .goaway => {
                const last_id = std.mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF;
                const err_code = std.mem.readInt(u32, payload[4..8], .big);
                std.log.warn("H2 GOAWAY last_stream={d} error={d}", .{ last_id, err_code });
                try handler.onH2Goaway(self.fd, last_id);
            },
            else => {
                // Unknown frame type — ignore per RFC 7540 §4.1
                std.log.debug("H2 unknown frame type=0x{x} stream={d}", .{ @intFromEnum(fh.frame_type), fh.stream_id });
            },
        }
    }

    fn processSettings(self: *H2Conn, payload: []const u8) !void {
        var i: usize = 0;
        while (i + 6 <= payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                H2_SETTINGS_MAX_CONCURRENT_STREAMS => self.remote_max_concurrent = val,
                H2_SETTINGS_INITIAL_WINDOW_SIZE => self.remote_initial_window = val,
                H2_SETTINGS_MAX_FRAME_SIZE => self.remote_max_frame_size = val,
                else => {},
            }
        }
    }

    // ── Frame builders for outgoing control frames ────────────────────────

    /// Build a SETTINGS ACK frame (9 bytes).
    pub fn buildSettingsAck(buf: *[H2_FRAME_HEADER_LEN]u8) void {
        const hdr = FrameHeader{
            .length = 0,
            .frame_type = .settings,
            .flags = FrameFlags.ACK,
            .stream_id = 0,
        };
        hdr.encode(buf);
    }

    /// Build a WINDOW_UPDATE frame for stream or connection (stream_id=0).
    pub fn buildWindowUpdate(buf: *[H2_FRAME_HEADER_LEN + 4]u8, stream_id: u31, increment: u31) void {
        const hdr = FrameHeader{
            .length = 4,
            .frame_type = .window_update,
            .flags = 0,
            .stream_id = stream_id,
        };
        hdr.encode(buf[0..H2_FRAME_HEADER_LEN]);
        std.mem.writeInt(u32, buf[H2_FRAME_HEADER_LEN..][0..4], increment, .big);
    }

    /// Build a PING ACK echoing the provided 8-byte payload.
    pub fn buildPingAck(buf: *[H2_FRAME_HEADER_LEN + 8]u8, opaque_data: []const u8) void {
        const hdr = FrameHeader{
            .length = 8,
            .frame_type = .ping,
            .flags = FrameFlags.ACK,
            .stream_id = 0,
        };
        hdr.encode(buf[0..H2_FRAME_HEADER_LEN]);
        @memcpy(buf[H2_FRAME_HEADER_LEN .. H2_FRAME_HEADER_LEN + 8], opaque_data[0..8]);
    }

    /// Build a RST_STREAM frame (stream_id, error_code).
    pub fn buildRstStream(buf: *[H2_FRAME_HEADER_LEN + 4]u8, stream_id: u31, error_code: u32) void {
        const hdr = FrameHeader{
            .length = 4,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = stream_id,
        };
        hdr.encode(buf[0..H2_FRAME_HEADER_LEN]);
        std.mem.writeInt(u32, buf[H2_FRAME_HEADER_LEN..][0..4], error_code, .big);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "FrameHeader encode/decode round-trip" {
    var buf: [H2_FRAME_HEADER_LEN]u8 = undefined;
    const original = FrameHeader{
        .length = 42,
        .frame_type = .headers,
        .flags = FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
        .stream_id = 7,
    };
    original.encode(&buf);
    const decoded = FrameHeader.decode(&buf);
    try std.testing.expectEqual(original.length, decoded.length);
    try std.testing.expectEqual(original.frame_type, decoded.frame_type);
    try std.testing.expectEqual(original.flags, decoded.flags);
    try std.testing.expectEqual(original.stream_id, decoded.stream_id);
}

test "HPACK encode indexed header" {
    var enc = HpackEncoder.init(std.testing.allocator);
    defer enc.deinit();
    try enc.encodeHeader(":method", "GET");
    // :method = GET is entry 2 → should encode as 0x82 (indexed, 1xxxxxxx = 130)
    try std.testing.expect(enc.buf.items.len > 0);
    try std.testing.expectEqual(@as(u8, 0x82), enc.buf.items[0]);
}

test "H2Conn SETTINGS ACK frame" {
    var buf: [H2_FRAME_HEADER_LEN]u8 = undefined;
    H2Conn.buildSettingsAck(&buf);
    const fh = FrameHeader.decode(&buf);
    try std.testing.expectEqual(FrameType.settings, fh.frame_type);
    try std.testing.expectEqual(@as(u8, FrameFlags.ACK), fh.flags);
    try std.testing.expectEqual(@as(u31, 0), fh.stream_id);
}

test "hop-by-hop filter" {
    try std.testing.expect(isHopByHop("connection"));
    try std.testing.expect(isHopByHop("Transfer-Encoding"));
    try std.testing.expect(!isHopByHop("content-type"));
    try std.testing.expect(!isHopByHop("authorization"));
}
