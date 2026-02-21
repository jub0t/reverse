/// worker.zig — per-CPU worker thread
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

const Ring = @import("io/ring.zig").Ring;
const RingConfig = @import("io/ring.zig").RingConfig;
const Tag = @import("io/ring.zig").Tag;
const parser = @import("http/parser.zig");
const pool_mod = @import("upstream/pool.zig");
const LocalPool = pool_mod.LocalPool;
const LoadBalancer = pool_mod.LoadBalancer;
const Config = @import("config.zig").Config;

/// Global shutdown flag. Set by main thread on Ctrl+C.
/// Workers check this every ~100ms via recurring TIMEOUT SQE.
pub var shutdown_flag = std.atomic.Value(bool).init(false);

// ── Per-connection state ──────────────────────────────────────────────────────

const ConnState = enum {
    reading_request,
    connecting_upstream,
    forwarding,
    sending_response,
    closing,
};

const Conn = struct {
    client_fd: std.posix.fd_t,
    upstream_fd: std.posix.fd_t = -1,
    state: ConnState = .reading_request,
    req_buf: [8192]u8 = undefined,
    req_len: usize = 0,
    parsed: parser.Request = undefined,
    upstream: *pool_mod.Upstream = undefined,
    keepalive: bool = true,
};

// ── Worker ────────────────────────────────────────────────────────────────────

pub const WorkerConfig = struct {
    id: u32,
    listen_fd: std.posix.fd_t,
    cfg: *const Config,
    lb: *LoadBalancer,
    allocator: std.mem.Allocator,
};

pub const Worker = struct {
    wcfg: WorkerConfig,
    ring: Ring,
    local_pool: LocalPool,
    conns: std.AutoHashMap(std.posix.fd_t, Conn),

    pub fn init(wcfg: WorkerConfig) !Worker {
        const ring_cfg = RingConfig{
            .sq_depth = wcfg.cfg.io_uring_sq_depth,
            .buf_count = wcfg.cfg.io_uring_buf_count,
            .buf_size = wcfg.cfg.io_uring_buf_size,
            .buf_group = @intCast(wcfg.id),
        };

        var ring = try Ring.init(wcfg.allocator, ring_cfg);
        errdefer ring.deinit();

        var local_pool = try LocalPool.init(
            wcfg.allocator,
            wcfg.cfg.upstream.pool_size,
        );
        errdefer local_pool.deinit(wcfg.allocator);

        return Worker{
            .wcfg = wcfg,
            .ring = ring,
            .local_pool = local_pool,
            .conns = std.AutoHashMap(std.posix.fd_t, Conn).init(wcfg.allocator),
        };
    }

    pub fn deinit(self: *Worker) void {
        self.ring.deinit();
        self.local_pool.deinit(self.wcfg.allocator);
        self.conns.deinit();
    }

    pub fn run(self: *Worker) !void {
        std.log.info("worker {d} starting (listen_fd={d})", .{
            self.wcfg.id, self.wcfg.listen_fd,
        });

        try self.ring.submitMultishotAccept(self.wcfg.listen_fd);

        // Recurring 100ms timeout so we wake up and check shutdown_flag
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

        const conn = Conn{ .client_fd = client_fd };
        try self.conns.put(client_fd, conn);
        try self.ring.submitMultishotRecv(client_fd);

        std.log.debug("worker {d} accepted fd={d}", .{ self.wcfg.id, client_fd });
    }

    pub fn onRecv(self: *Worker, client_fd: std.posix.fd_t, data: []u8, buf_idx: u16) !void {
        _ = buf_idx;

        const conn = self.conns.getPtr(client_fd) orelse return;

        switch (conn.state) {
            .reading_request => {
                const available = conn.req_buf.len - conn.req_len;
                const to_copy = @min(data.len, available);
                @memcpy(conn.req_buf[conn.req_len .. conn.req_len + to_copy], data[0..to_copy]);
                conn.req_len += to_copy;

                const consumed = parser.parse(
                    conn.req_buf[0..conn.req_len],
                    &conn.parsed,
                ) catch |err| switch (err) {
                    error.NeedMoreData => return,
                    else => {
                        try self.sendBadRequest(client_fd);
                        return;
                    },
                };
                _ = consumed;

                conn.keepalive = (conn.parsed.version == 11);
                if (conn.parsed.header("connection")) |v| {
                    if (std.ascii.eqlIgnoreCase(v, "close")) conn.keepalive = false;
                    if (std.ascii.eqlIgnoreCase(v, "keep-alive")) conn.keepalive = true;
                }

                conn.upstream = self.wcfg.lb.pick();

                if (self.local_pool.pop(conn.upstream)) |ufd| {
                    conn.upstream_fd = ufd;
                    conn.state = .forwarding;
                    try self.forwardRequest(conn);
                } else {
                    conn.upstream_fd = try pool_mod.connectNew(conn.upstream, .{});
                    conn.state = .connecting_upstream;
                    std.log.debug("connecting new upstream fd={d}", .{conn.upstream_fd});
                }
            },
            .forwarding => {
                try self.ring.submitSend(client_fd, data);
            },
            else => {},
        }
    }

    pub fn onSend(self: *Worker, fd: std.posix.fd_t, _: usize) !void {
        const conn = self.conns.getPtr(fd) orelse return;
        if (conn.state == .sending_response) {
            if (conn.keepalive) {
                conn.state = .reading_request;
                conn.req_len = 0;
            } else {
                try self.ring.submitClose(fd);
                conn.state = .closing;
            }
        }
    }

    pub fn onConnect(self: *Worker, upstream_fd: std.posix.fd_t, success: bool) !void {
        var it = self.conns.valueIterator();
        while (it.next()) |conn| {
            if (conn.upstream_fd == upstream_fd) {
                if (!success) {
                    conn.upstream.healthy.store(false, .release);
                    try self.sendError(conn.client_fd, 502, "Bad Gateway");
                    return;
                }
                conn.state = .forwarding;
                try self.forwardRequest(conn);
                return;
            }
        }
    }

    pub fn onClose(self: *Worker, fd: std.posix.fd_t) !void {
        if (self.conns.fetchRemove(fd)) |entry| {
            const conn = entry.value;
            if (conn.upstream_fd >= 0) {
                self.local_pool.push(conn.upstream_fd, conn.upstream);
            }
        }
        std.log.debug("worker {d} closed fd={d}", .{ self.wcfg.id, fd });
    }

    pub fn onError(self: *Worker, fd: std.posix.fd_t, tag: Tag, err: linux.E) !void {
        std.log.debug("worker {d} error fd={d} tag={s} err={s}", .{
            self.wcfg.id, fd, @tagName(tag), @tagName(err),
        });
        if (tag == .recv or tag == .accept) {
            try self.ring.submitClose(fd);
        }
    }

    pub fn onTimeout(self: *Worker) !void {
        // Woke up from the recurring timeout — loop condition will check
        // shutdown_flag. Resubmit so we keep waking up every 100ms.
        if (!shutdown_flag.load(.acquire)) {
            try self.ring.submitTimeout(100);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn forwardRequest(self: *Worker, conn: *Conn) !void {
        const raw = conn.req_buf[0..conn.req_len];
        try self.ring.submitSend(conn.upstream_fd, raw);
        conn.state = .forwarding;
    }

    fn sendBadRequest(self: *Worker, fd: std.posix.fd_t) !void {
        try self.sendError(fd, 400, "Bad Request");
    }

    fn sendError(self: *Worker, fd: std.posix.fd_t, code: u16, msg: []const u8) !void {
        var buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(
            &buf,
            "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{ code, msg },
        ) catch unreachable;
        try self.ring.submitSend(fd, resp);
    }
};

// ── Thread entrypoint ─────────────────────────────────────────────────────────

pub fn workerThread(wcfg: WorkerConfig) void {
    var arena = std.heap.ArenaAllocator.init(wcfg.allocator);
    defer arena.deinit();

    var cfg_with_arena = wcfg;
    cfg_with_arena.allocator = arena.allocator();

    var w = Worker.init(cfg_with_arena) catch |err| {
        std.log.err("worker {d} init failed: {}", .{ wcfg.id, err });
        return;
    };
    defer w.deinit();

    w.run() catch |err| {
        std.log.err("worker {d} crashed: {}", .{ wcfg.id, err });
    };
}
