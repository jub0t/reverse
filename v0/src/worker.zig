/// worker.zig — per-CPU worker thread
///
/// Key architectural changes from v1:
///
///   1. Dual maps: `client_conns` (client_fd → Conn) and `upstream_map`
///      (upstream_fd → client_fd). CQEs arrive tagged with whichever fd
///      fired — the upstream_map lets us route upstream recv/send CQEs back
///      to the right Conn without a linear scan.
///
///   2. Separate req_buf / resp_buf: the 8KB req_buf holds the client request
///      while the 64KB resp_buf receives the upstream response. They never
///      alias each other.
///
///   3. Async connect: after connectNew() creates the socket, we immediately
///      submit IORING_OP_CONNECT so onConnect() is called by the ring on
///      completion rather than relying on a blocking syscall inside the loop.
///
///   4. Correct state machine:
///        reading_request → connecting_upstream | forwarding_request
///        connecting_upstream → forwarding_request   (onConnect success)
///        forwarding_request → waiting_response      (send to upstream done)
///        waiting_response → sending_response        (recv from upstream)
///        sending_response → reading_request | closing (send to client done)
///
///   5. onSend dispatches by which fd fired: upstream sends arm upstream
///      recv; client sends handle keepalive/close.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

const Ring = @import("io/ring.zig").Ring;
const RingConfig = @import("io/ring.zig").RingConfig;
const Tag = @import("io/ring.zig").Tag;
const parser = @import("http/parser.zig");
const pool_mod = @import("upstream/pool.zig");
const LocalPool = pool_mod.LocalPool;
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const main_mod = @import("main.zig");
const ServerRuntime = main_mod.ServerRuntime;
const PoolRuntime = main_mod.PoolRuntime;

/// Global shutdown flag — set by main on Ctrl+C.
pub var shutdown_flag = std.atomic.Value(bool).init(false);

// ── State machine ─────────────────────────────────────────────────────────────

const ConnState = enum {
    /// Waiting for / reading the client HTTP request
    reading_request,
    /// TCP connect SQE submitted to upstream — waiting for CONNECT CQE
    connecting_upstream,
    /// Sending the request to upstream via io_uring SEND
    forwarding_request,
    /// Request sent — waiting for upstream response (recv SQE armed on upstream_fd)
    waiting_response,
    /// Upstream responded — sending it back to the client
    sending_response,
    /// Close SQE submitted
    closing,
};

// ── Per-connection state ──────────────────────────────────────────────────────

const RESP_BUF_SIZE = 65536; // 64 KB — enough for most HTTP responses

const Conn = struct {
    client_fd: std.posix.fd_t,
    upstream_fd: std.posix.fd_t = -1,
    state: ConnState = .reading_request,

    /// Client request buffer — 8 KB, passed directly to RECV SQE.
    req_buf: [8192]u8 = undefined,
    req_len: usize = 0,

    /// Upstream response buffer — 64 KB, passed to RECV SQE on upstream_fd.
    /// Heap-allocated to keep Conn size reasonable in the HashMap.
    resp_buf: []u8,

    parsed: parser.Request = undefined,
    upstream: *pool_mod.Upstream = undefined,
    keepalive: bool = true,
};

// ── Worker config ─────────────────────────────────────────────────────────────

pub const WorkerConfig = struct {
    id: u32,
    /// One fd per server block — worker arms multishot accept on all of them.
    listen_fds: []const std.posix.fd_t,
    cfg: *const Config,
    /// One runtime per server block — holds live LoadBalancers for each pool.
    server_runtimes: []const ServerRuntime,
    allocator: std.mem.Allocator,
};

// ── Worker ────────────────────────────────────────────────────────────────────

pub const Worker = struct {
    wcfg: WorkerConfig,
    ring: Ring,
    local_pool: LocalPool,

    /// Primary map: client_fd → Conn
    client_conns: std.AutoHashMap(std.posix.fd_t, Conn),
    /// Reverse map: upstream_fd → client_fd
    /// Lets us route CQEs for upstream fds back to the right Conn in O(1).
    upstream_map: std.AutoHashMap(std.posix.fd_t, std.posix.fd_t),
    /// Set of fds that have been closed and removed from both maps.
    /// Any CQE arriving for an fd in this set is a stale in-flight CQE
    /// from before the close — silently drop it.
    /// Entries are removed when a new connection is accepted on the same fd
    /// (OS fd reuse), at which point the fd is live again.
    closing_fds: std.AutoHashMap(std.posix.fd_t, void),

    pub fn init(wcfg: WorkerConfig) !Worker {
        // Use the first server's first pool size as the local pool capacity.
        // Each Conn tracks which pool its upstream belongs to directly.
        const pool_size: u32 = if (wcfg.server_runtimes.len > 0 and
            wcfg.server_runtimes[0].pools.len > 0)
            wcfg.server_runtimes[0].server_cfg.upstream_pools[0].pool_size
        else
            64;

        const ring_cfg = RingConfig{
            .sq_depth = wcfg.cfg.global.io_uring_sq_depth,
            .buf_count = wcfg.cfg.global.io_uring_buf_count,
            .buf_size = wcfg.cfg.global.io_uring_buf_size,
            .buf_group = @intCast(wcfg.id),
        };

        var ring = try Ring.init(wcfg.allocator, ring_cfg);
        errdefer ring.deinit();

        var local_pool = try LocalPool.init(wcfg.allocator, pool_size);
        errdefer local_pool.deinit(wcfg.allocator);

        return Worker{
            .wcfg = wcfg,
            .ring = ring,
            .local_pool = local_pool,
            .client_conns = std.AutoHashMap(std.posix.fd_t, Conn).init(wcfg.allocator),
            .upstream_map = std.AutoHashMap(std.posix.fd_t, std.posix.fd_t).init(wcfg.allocator),
            .closing_fds = std.AutoHashMap(std.posix.fd_t, void).init(wcfg.allocator),
        };
    }

    pub fn deinit(self: *Worker) void {
        // Free all resp_buf allocations before deiniting the maps
        var it = self.client_conns.valueIterator();
        while (it.next()) |conn| {
            self.wcfg.allocator.free(conn.resp_buf);
        }
        self.ring.deinit();
        self.local_pool.deinit(self.wcfg.allocator);
        self.client_conns.deinit();
        self.upstream_map.deinit();
        self.closing_fds.deinit();
    }

    pub fn run(self: *Worker) !void {
        std.log.info("worker {d} starting ({d} servers)", .{
            self.wcfg.id, self.wcfg.listen_fds.len,
        });

        for (self.wcfg.listen_fds) |fd| {
            try self.ring.submitMultishotAccept(fd);
        }
        try self.ring.submitTimeout(100);

        while (!shutdown_flag.load(.acquire)) {
            self.ring.waitAndDispatch(self) catch |err| switch (err) {
                error.FileDescriptorInvalid,
                error.Unexpected,
                => break,
                else => return err,
            };
        }

        std.log.info("worker {d} stopped", .{self.wcfg.id});
    }

    // ── CQE handlers ─────────────────────────────────────────────────────────

    pub fn onAccept(self: *Worker, _: std.posix.fd_t, client_fd: i32) !void {
        _ = linux.fcntl(client_fd, linux.F.SETFL, @as(usize, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))));

        // OS reused this fd for a new connection — it's live again.
        _ = self.closing_fds.remove(client_fd);

        const resp_buf = try self.wcfg.allocator.alloc(u8, RESP_BUF_SIZE);
        errdefer self.wcfg.allocator.free(resp_buf);

        try self.client_conns.put(client_fd, Conn{
            .client_fd = client_fd,
            .resp_buf = resp_buf,
        });
        const conn = self.client_conns.getPtr(client_fd).?;

        try self.ring.submitRecv(client_fd, &conn.req_buf);
        std.log.debug("worker {d} accepted fd={d}", .{ self.wcfg.id, client_fd });
    }

    /// onRecv is called for BOTH client fds and upstream fds.
    /// We check upstream_map first: if the fd is in the upstream map, we're
    /// receiving a response from upstream and should forward it to the client.
    pub fn onRecv(self: *Worker, fd: std.posix.fd_t, bytes: i32) !void {
        // Drop stale CQEs for already-closed fds
        if (self.closing_fds.contains(fd)) return;
        // ── Upstream response path ────────────────────────────────────────
        if (self.upstream_map.get(fd)) |client_fd| {
            const conn = self.client_conns.getPtr(client_fd) orelse {
                // Client already gone — close upstream too
                try self.ring.submitClose(fd);
                _ = self.upstream_map.remove(fd);
                return;
            };

            const data = conn.resp_buf[0..@intCast(bytes)];
            conn.state = .sending_response;
            // Forward response to client
            try self.ring.submitSend(client_fd, data);
            // Re-arm upstream recv for more data (streaming responses, chunked, etc.)
            // This is submitted after the send — both will be in flight concurrently.
            try self.ring.submitRecv(fd, conn.resp_buf);
            return;
        }

        // ── Client request path ───────────────────────────────────────────
        const conn = self.client_conns.getPtr(fd) orelse return;

        conn.req_len += @intCast(bytes);

        const consumed = parser.parse(
            conn.req_buf[0..conn.req_len],
            &conn.parsed,
        ) catch |err| switch (err) {
            error.NeedMoreData => {
                // Re-arm recv into the remainder of the buffer
                try self.ring.submitRecv(fd, conn.req_buf[conn.req_len..]);
                return;
            },
            else => {
                try self.sendErrorToClient(fd, 400, "Bad Request");
                return;
            },
        };
        _ = consumed;

        // Wait until the full body is buffered before forwarding
        if (!conn.parsed.isComplete(conn.req_len)) {
            if (conn.req_len >= conn.req_buf.len) {
                // Buffer full and still incomplete — 413
                try self.sendErrorToClient(fd, 413, "Payload Too Large");
                return;
            }
            try self.ring.submitRecv(fd, conn.req_buf[conn.req_len..]);
            return;
        }

        conn.keepalive = (conn.parsed.version == 11);
        if (conn.parsed.header("connection")) |v| {
            if (std.ascii.eqlIgnoreCase(v, "close")) conn.keepalive = false;
            if (std.ascii.eqlIgnoreCase(v, "keep-alive")) conn.keepalive = true;
        }

        // ── Route: match server block by Host header ──────────────────────
        const host = conn.parsed.header("host") orelse "";
        const bare_host = if (std.mem.lastIndexOfScalar(u8, host, ':')) |ci| host[0..ci] else host;

        var server_idx: usize = 0; // default: first server block
        outer: for (self.wcfg.server_runtimes, 0..) |*rt, i| {
            for (rt.server_cfg.server_name) |name| {
                if (std.ascii.eqlIgnoreCase(name, bare_host)) {
                    server_idx = i;
                    break :outer;
                }
                // Wildcard: *.example.com
                if (std.mem.startsWith(u8, name, "*.")) {
                    if (std.mem.endsWith(u8, bare_host, name[1..])) {
                        server_idx = i;
                        break :outer;
                    }
                }
            }
        }
        const srv_rt: *ServerRuntime = @constCast(&self.wcfg.server_runtimes[server_idx]);
        const srv_cfg = srv_rt.server_cfg;

        // ── Route: match location by path ─────────────────────────────────
        const loc = config_mod.matchLocation(srv_cfg, conn.parsed.path) orelse {
            try self.sendErrorToClient(fd, 404, "Not Found");
            return;
        };

        // ── Route: resolve upstream pool ──────────────────────────────────
        const pool_rt = srv_rt.findPool(loc.upstream_pool) orelse {
            std.log.err("worker {d}: pool '{s}' not found for location '{s}'", .{ self.wcfg.id, loc.upstream_pool, loc.match });
            try self.sendErrorToClient(fd, 502, "Bad Gateway");
            return;
        };

        conn.upstream = pool_rt.lb.pick();

        if (self.local_pool.pop(conn.upstream)) |ufd| {
            // Reuse an idle connection from the pool
            conn.upstream_fd = ufd;
            conn.state = .forwarding_request;
            try self.upstream_map.put(ufd, fd);
            try self.forwardRequest(conn);
        } else {
            // Open a new connection asynchronously
            const ufd = try pool_mod.connectNew(conn.upstream, .{});
            conn.upstream_fd = ufd;
            conn.state = .connecting_upstream;
            // Register in upstream_map immediately so onConnect can find the Conn
            try self.upstream_map.put(ufd, fd);
            // Submit async connect SQE — onConnect fires when it completes
            try self.ring.submitConnect(
                ufd,
                &conn.upstream.addr.any,
                conn.upstream.addr.getOsSockLen(),
            );
            std.log.debug("worker {d} connecting new upstream fd={d}", .{ self.wcfg.id, ufd });
        }
    }

    pub fn onSend(self: *Worker, fd: std.posix.fd_t, _: usize) !void {
        // Drop stale CQEs for already-closed fds
        if (self.closing_fds.contains(fd)) return;
        // ── Was this a send to an upstream fd? ────────────────────────────
        if (self.upstream_map.contains(fd)) {
            // We finished sending the request to upstream.
            // The upstream recv was already armed in onRecv (client path) via
            // forwardRequest → we don't need to arm it again here. Nothing to do.
            return;
        }

        // ── Send to client completed ──────────────────────────────────────
        const conn = self.client_conns.getPtr(fd) orelse return;

        if (conn.state == .sending_response) {
            if (conn.keepalive) {
                // Reset for next request on this connection
                conn.state = .reading_request;
                conn.req_len = 0;
                try self.ring.submitRecv(fd, &conn.req_buf);
            } else {
                conn.state = .closing;
                try self.ring.submitClose(fd);
            }
        }
    }

    pub fn onConnect(self: *Worker, upstream_fd: std.posix.fd_t, success: bool) !void {
        // Drop stale CQEs for already-closed fds
        if (self.closing_fds.contains(upstream_fd)) return;
        const client_fd = self.upstream_map.get(upstream_fd) orelse return;
        const conn = self.client_conns.getPtr(client_fd) orelse {
            // Client gone — close upstream
            try self.ring.submitClose(upstream_fd);
            _ = self.upstream_map.remove(upstream_fd);
            return;
        };

        if (!success) {
            conn.upstream.healthy.store(false, .release);
            _ = self.upstream_map.remove(upstream_fd);
            conn.upstream_fd = -1;
            try self.sendErrorToClient(client_fd, 502, "Bad Gateway");
            return;
        }

        // Connected — increment active count and forward the request
        conn.upstream.incActive();
        conn.state = .forwarding_request;
        try self.forwardRequest(conn);
        std.log.debug("worker {d} upstream fd={d} connected", .{ self.wcfg.id, upstream_fd });
    }

    pub fn onClose(self: *Worker, fd: std.posix.fd_t) !void {
        // Drop stale CQEs — this fd was already handled
        if (self.closing_fds.contains(fd)) return;

        // Was this an upstream fd closing?
        if (self.upstream_map.fetchRemove(fd)) |entry| {
            const client_fd = entry.value;
            // Mark upstream fd as closed to suppress stale CQEs
            try self.closing_fds.put(fd, {});

            if (self.client_conns.getPtr(client_fd)) |conn| {
                conn.upstream_fd = -1;
                if (conn.state == .waiting_response or conn.state == .connecting_upstream) {
                    // Upstream closed before we got a response — close client too
                    conn.state = .closing;
                    try self.closing_fds.put(client_fd, {});
                    try self.ring.submitClose(client_fd);
                }
                // If we're in sending_response, the response is already on its way
                // to the client — let onSend handle the keepalive/close transition.
            }
            std.log.debug("worker {d} upstream closed fd={d}", .{ self.wcfg.id, fd });
            return;
        }

        // Client fd closing
        if (self.client_conns.fetchRemove(fd)) |entry| {
            const conn = entry.value;
            defer self.wcfg.allocator.free(conn.resp_buf);
            // Mark client fd as closed
            try self.closing_fds.put(fd, {});
            if (conn.upstream_fd >= 0) {
                // Return upstream connection to the pool (or close if full/unhealthy)
                _ = self.upstream_map.remove(conn.upstream_fd);
                try self.closing_fds.put(conn.upstream_fd, {});
                self.local_pool.push(conn.upstream_fd, conn.upstream);
            }
        }
        std.log.debug("worker {d} closed fd={d}", .{ self.wcfg.id, fd });
    }

    pub fn onTimeout(self: *Worker) !void {
        if (!shutdown_flag.load(.acquire)) {
            try self.ring.submitTimeout(100);
        }
    }

    pub fn onError(self: *Worker, fd: std.posix.fd_t, tag: Tag, err: linux.E) !void {
        // Drop stale CQEs for already-closed fds
        if (self.closing_fds.contains(fd)) return;

        // res=0 on send/close/connect is a normal zero-byte or already-complete
        // result, not an error. The ring dispatcher routes res=0 to onClose for
        // recv (EOF), but for other tags res=0 just means success with no data.
        // Silently ignore — do NOT close or re-arm.
        if (err == .SUCCESS and tag != .recv) return;

        std.log.debug("worker {d} error fd={d} tag={s} err={s}", .{
            self.wcfg.id, fd, @tagName(tag), @tagName(err),
        });

        // EAGAIN on recv — re-arm
        if (err == .AGAIN and tag == .recv) {
            if (self.upstream_map.get(fd)) |client_fd| {
                if (self.client_conns.getPtr(client_fd)) |conn| {
                    try self.ring.submitRecv(fd, conn.resp_buf);
                    return;
                }
            }
            if (self.client_conns.getPtr(fd)) |conn| {
                try self.ring.submitRecv(fd, &conn.req_buf);
                return;
            }
        }

        // ECONNREFUSED on connect — mark unhealthy and send 502
        if (err == .CONNREFUSED and tag == .connect) {
            try self.onConnect(fd, false);
            return;
        }

        // Anything else: close (guard against double-close via closing_fds)
        if (tag == .recv or tag == .send or tag == .connect) {
            try self.closing_fds.put(fd, {});
            try self.ring.submitClose(fd);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Send the buffered client request to the upstream fd and arm a recv
    /// on the upstream fd for the response.
    fn forwardRequest(self: *Worker, conn: *Conn) !void {
        const raw = conn.req_buf[0..conn.req_len];
        try self.ring.submitSend(conn.upstream_fd, raw);
        // Arm upstream recv immediately — response may arrive before send CQE
        try self.ring.submitRecv(conn.upstream_fd, conn.resp_buf);
    }

    fn sendErrorToClient(self: *Worker, fd: std.posix.fd_t, code: u16, msg: []const u8) !void {
        // We need a stable buffer for the send. Use the conn's resp_buf if
        // available, otherwise a stack buffer for the error response.
        var buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(
            &buf,
            "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{ code, msg },
        ) catch unreachable;

        if (self.client_conns.getPtr(fd)) |conn| {
            conn.state = .closing;
            // Copy to resp_buf so the slice remains valid until the send CQE fires
            @memcpy(conn.resp_buf[0..resp.len], resp);
            try self.ring.submitSend(fd, conn.resp_buf[0..resp.len]);
        }
    }
};

// ── Thread entrypoint ─────────────────────────────────────────────────────────

pub fn workerThread(wcfg: WorkerConfig) void {
    // Use a GPA for the worker so individual allocations (resp_buf) can be
    // freed mid-session. An arena would leak resp_buf on every connection close.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cfg_with_gpa = wcfg;
    cfg_with_gpa.allocator = gpa.allocator();

    var w = Worker.init(cfg_with_gpa) catch |err| {
        std.log.err("worker {d} init failed: {}", .{ wcfg.id, err });
        return;
    };
    defer w.deinit();

    w.run() catch |err| {
        std.log.err("worker {d} crashed: {}", .{ wcfg.id, err });
    };
}
