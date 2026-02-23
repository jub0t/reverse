/// worker_routing.zig — routing extensions for TLS, H2 upstream, static files
///
/// This file documents the precise changes needed in worker.zig and the new
/// per-connection state additions required to support all three features.
/// Rather than replacing worker.zig wholesale, the diffs are described as
/// clearly delineated additions — easier to review and merge.
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 1. CONN STATE ADDITIONS
/// ═══════════════════════════════════════════════════════════════════════════
///
/// Add to ConnState enum in worker.zig:
///
///   tls_handshake,       // Phase 1: feeding bytes to OpenSSL BIO
///   sending_tls_output,  // Phase 1: draining handshake bytes to client
///   serving_static,      // Sendfile SQE in flight to client
///
/// Add to Conn struct in worker.zig:
///
///   /// Non-null when the client connection is TLS.
///   tls: ?*tls_mod.TlsConn = null,
///
///   /// Non-null when the upstream for this request is HTTP/2.
///   h2_conn: ?*h2_mod.H2Conn = null,
///   h2_stream_id: u31 = 0,
///
///   /// Non-null when serving a static file; fd closed in onSend.
///   static_file_fd: std.posix.fd_t = -1,
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 2. ACCEPT PATH — TLS detection
/// ═══════════════════════════════════════════════════════════════════════════
///
/// In onAccept, after creating the Conn:
///
///   // Determine whether this listen_fd is TLS-enabled.
///   // tls_contexts is a []?*TlsContext, parallel to listen_fds.
///   if (self.wcfg.tls_contexts[listen_idx]) |tls_ctx| {
///       conn.tls = try self.wcfg.allocator.create(tls_mod.TlsConn);
///       conn.tls.?.* = try tls_mod.TlsConn.init(tls_ctx);
///       conn.state = .tls_handshake;
///       // First recv already submitted; onRecv will feed bytes to OpenSSL.
///   }
///
/// WorkerConfig gains:
///   tls_contexts: []const ?*tls_mod.TlsContext,
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 3. RECV PATH — TLS handshake pump
/// ═══════════════════════════════════════════════════════════════════════════
///
/// At the TOP of onRecv (client request path), before the existing logic:
///
///   if (conn.tls) |tls| {
///       if (tls.state != .ktls_active) {
///           return self.pumpTlsHandshake(fd, conn, tls, bytes);
///       }
///       // kTLS active: io_uring already decrypted; fall through normally.
///   }
///
/// pumpTlsHandshake (new private method):
///
///   fn pumpTlsHandshake(
///       self: *Worker,
///       fd: std.posix.fd_t,
///       conn: *Conn,
///       tls: *tls_mod.TlsConn,
///       bytes: i32,
///   ) !void {
///       try tls.feedInput(conn.req_buf[0..@intCast(bytes)]);
///       const next = try tls.stepHandshake();
///       switch (next) {
///           .want_read => {
///               // May also have output to send first
///               if (tls.pendingOutputLen() > 0) {
///                   const n = tls.drainOutput(conn.resp_buf);
///                   conn.state = .sending_tls_output;
///                   try self.ring.submitSend(fd, conn.resp_buf[0..n]);
///               } else {
///                   try self.ring.submitRecv(fd, &conn.req_buf);
///               }
///           },
///           .want_write => {
///               const n = tls.drainOutput(conn.resp_buf);
///               conn.state = .sending_tls_output;
///               try self.ring.submitSend(fd, conn.resp_buf[0..n]);
///           },
///           .established => {
///               // Try kTLS upgrade
///               tls.upgradeToKtls(fd) catch {};
///               // Drain any final handshake output
///               if (tls.pendingOutputLen() > 0) {
///                   const n = tls.drainOutput(conn.resp_buf);
///                   conn.state = .sending_tls_output;
///                   try self.ring.submitSend(fd, conn.resp_buf[0..n]);
///               } else {
///                   conn.state = .reading_request;
///                   try self.ring.submitRecv(fd, &conn.req_buf);
///               }
///               // Use ALPN result to set H2 mode
///               if (tls.protocol == .h2) conn.use_h2 = true;
///           },
///           else => try self.sendErrorToClient(fd, 500, "TLS error"),
///       }
///   }
///
/// In onSend, add a case for .sending_tls_output:
///
///   if (conn.state == .sending_tls_output) {
///       if (conn.tls.?.pendingOutputLen() > 0) {
///           const n = conn.tls.?.drainOutput(conn.resp_buf);
///           try self.ring.submitSend(fd, conn.resp_buf[0..n]);
///       } else if (conn.tls.?.state == .established or conn.tls.?.state == .ktls_active) {
///           conn.state = .reading_request;
///           try self.ring.submitRecv(fd, &conn.req_buf);
///       }
///       return;
///   }
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 4. ROUTING — static files (configless)
/// ═══════════════════════════════════════════════════════════════════════════
///
/// In onRecv, after request is parsed and complete, BEFORE upstream routing:
///
///   // Static file check: if the location has a static root configured,
///   // OR if a per-request header X-Static-Root is present (dev mode),
///   // serve directly without touching the upstream pool.
///   const static_root: ?[]const u8 = blk: {
///       if (loc.static) |s| break :blk s.root;
///       // Configless: check for X-Static-Root header (remove in prod)
///       break :blk conn.parsed.header("x-static-root");
///   };
///
///   if (static_root) |root| {
///       const inm = conn.parsed.header("if-none-match");
///       const ims = conn.parsed.header("if-modified-since");
///       const rng = conn.parsed.header("range");
///
///       const file_resp = static_mod.prepareFileResponse(
///           root, conn.parsed.path,
///           inm, ims, rng,
///           self.wcfg.allocator,
///       ) catch {
///           try self.sendErrorToClient(fd, 500, "Internal Server Error");
///           return;
///       };
///
///       // Send headers first
///       @memcpy(conn.resp_buf[0..file_resp.header_len], file_resp.header_buf[0..file_resp.header_len]);
///       conn.state = .sending_response;
///       try self.ring.submitSend(fd, conn.resp_buf[0..file_resp.header_len]);
///
///       // Submit sendfile for the body (if any)
///       if (static_mod.makeSendfileOp(&file_resp, fd)) |op| {
///           conn.static_file_fd = op.in_fd;
///           try self.ring.submitSendfile(op, fd);
///       }
///       return;
///   }
///
/// In onSend, when conn.static_file_fd >= 0 and sendfile CQE arrives:
///
///   if (conn.static_file_fd >= 0) {
///       std.posix.close(conn.static_file_fd);
///       conn.static_file_fd = -1;
///   }
///   // Then normal keepalive/close transition
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 5. ROUTING — HTTP/2 upstream
/// ═══════════════════════════════════════════════════════════════════════════
///
/// H2 upstreams are detected from pool_cfg.protocol == .h2 (new field in config).
/// When H2 is active, instead of connectNew() → forwardRequest():
///
///   const h2up = pool_rt.h2_upstream; // H2Upstream, one per pool
///   const h2conn = try h2up.acquireConn(self.wcfg.allocator);
///   conn.h2_conn = h2conn;
///
///   var frame_buf: [16 + 4096]u8 = undefined;
///   const result = try h2conn.openStream(
///       fd,
///       conn.parsed.method_str,
///       conn.parsed.path,
///       conn.parsed.header("host") orelse "",
///       conn.parsed.headers[0..conn.parsed.header_count],
///       &frame_buf,
///   );
///   conn.h2_stream_id = result.stream_id;
///   try self.ring.submitSend(h2conn.fd, frame_buf[0..result.len]);
///
/// H2 response callbacks (implement on Worker):
///
///   pub fn onH2ResponseHeaders(self: *Worker, client_fd: std.posix.fd_t, stream_id: u31, hpack_block: []const u8) !void {
///       // Decode hpack_block → HTTP/1.1 response headers → submitSend to client
///       var decoded: [64]h2_mod.HpackDecoder.DecodedHeader = undefined;
///       const count = try h2_mod.HpackDecoder.decode(hpack_block, &decoded, self.wcfg.allocator);
///       // Build HTTP/1.1 response header string and send to client
///       _ = stream_id;
///       _ = count;
///   }
///
///   pub fn onH2ResponseData(self: *Worker, client_fd: std.posix.fd_t, _: u31, data: []const u8) !void {
///       // Forward data chunk directly to client
///       if (self.client_conns.getPtr(client_fd)) |conn| {
///           @memcpy(conn.resp_buf[0..data.len], data);
///           try self.ring.submitSend(client_fd, conn.resp_buf[0..data.len]);
///       }
///   }
///
///   pub fn onH2StreamEnd(self: *Worker, client_fd: std.posix.fd_t, _: u31) !void {
///       if (self.client_conns.getPtr(client_fd)) |conn| {
///           conn.state = .sending_response;
///           conn.h2_conn = null;
///           conn.h2_stream_id = 0;
///       }
///   }
///
///   pub fn onH2SettingsAck(self: *Worker, upstream_fd: std.posix.fd_t) !void {
///       var ack_buf: [9]u8 = undefined;
///       h2_mod.H2Conn.buildSettingsAck(&ack_buf);
///       try self.ring.submitSend(upstream_fd, &ack_buf);
///   }
///
///   pub fn onH2WindowUpdate(self: *Worker, upstream_fd: std.posix.fd_t, stream_id: u31, increment: u31) !void {
///       var wu_buf: [13]u8 = undefined;
///       h2_mod.H2Conn.buildWindowUpdate(&wu_buf, stream_id, increment);
///       try self.ring.submitSend(upstream_fd, &wu_buf);
///       // Also send connection-level window update
///       h2_mod.H2Conn.buildWindowUpdate(&wu_buf, 0, increment);
///       try self.ring.submitSend(upstream_fd, &wu_buf);
///   }
///
///   pub fn onH2Goaway(self: *Worker, upstream_fd: std.posix.fd_t, _: u31) !void {
///       // Drain remaining streams, then close the H2 connection
///       try self.ring.submitClose(upstream_fd);
///   }
///
///   pub fn onH2PingAck(self: *Worker, upstream_fd: std.posix.fd_t, data: []const u8) !void {
///       var ping_buf: [17]u8 = undefined;
///       h2_mod.H2Conn.buildPingAck(&ping_buf, data);
///       try self.ring.submitSend(upstream_fd, &ping_buf);
///   }
///
///   pub fn onH2StreamError(self: *Worker, client_fd: std.posix.fd_t, _: u31) !void {
///       try self.sendErrorToClient(client_fd, 502, "Bad Gateway");
///   }
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 6. CONN CLEANUP
/// ═══════════════════════════════════════════════════════════════════════════
///
/// In onClose (client fd path), after freeing resp_buf:
///
///   if (conn.tls) |tls| {
///       tls.deinit();
///       self.wcfg.allocator.destroy(tls);
///   }
///   if (conn.static_file_fd >= 0) {
///       std.posix.close(conn.static_file_fd);
///   }
///   // H2 stream cleanup: the H2Conn is owned by the pool, not the Conn.
///   // The stream is cleaned up by onH2StreamEnd / onH2StreamError.
///
/// ═══════════════════════════════════════════════════════════════════════════
/// 7. CONN MEMORY NOTE
/// ═══════════════════════════════════════════════════════════════════════════
///
/// TlsConn is heap-allocated (allocator.create) because it contains an
/// OpenSSL SSL* pointer (8 bytes) plus two BIO* pointers — tiny, but we
/// want the Conn struct to remain a fixed-size value type in the HashMap
/// rather than bloating with rarely-used fields.
///
/// H2Conn is owned by the H2Upstream pool, not by Conn. Conn merely holds
/// a pointer to the shared H2Conn and a stream_id. This is correct because
/// a single H2Conn may serve dozens of concurrent Conns.
const std = @import("std");
const tls_mod = @import("tls/context.zig");
const h2_mod = @import("upstream/h2.zig");
const static_mod = @import("static/serve.zig");

/// Extended WorkerConfig with TLS contexts.
/// Drop-in replacement for the existing WorkerConfig — adds one field.
pub const WorkerConfigV2 = struct {
    id: u32,
    listen_fds: []const std.posix.fd_t,
    cfg: *const @import("config.zig").Config,
    server_runtimes: []const @import("main.zig").ServerRuntime,
    allocator: std.mem.Allocator,
    /// One entry per listen_fd. Null = plaintext, non-null = TLS on that port.
    tls_contexts: []const ?*tls_mod.TlsContext,
};

/// Add to build_options in build.zig:
///   const sendfile = b.option(bool, "sendfile", "Use IORING_OP_SENDFILE") orelse true;
///   options.addOption(bool, "sendfile", sendfile);
pub const build_options_additions =
    \\// New build flags (add to build.zig options block):
    \\//   sendfile: bool  — use IORING_OP_SENDFILE for static files (Linux 5.6+)
    \\//   h2_upstream: bool — compile HTTP/2 upstream support
    \\//   tls: bool       — compile TLS termination support
;
