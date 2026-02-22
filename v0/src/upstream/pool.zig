/// upstream/pool.zig — per-worker upstream connection pool
///
/// Each worker thread owns one LocalPool. The pool is a simple fixed-size
/// stack of idle file descriptors — no mutex needed because only the owning
/// worker ever touches it.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

/// Re-export Strategy from config so callers only need one import.
pub const Strategy = @import("../config.zig").Strategy;

// ── Upstream address ──────────────────────────────────────────────────────────

pub const Upstream = struct {
    addr: std.net.Address,
    /// Active connection count (for least-connections LB)
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Total requests handled (for round-robin stats)
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Health: false when a connect or request fails
    healthy: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn incActive(self: *Upstream) void {
        _ = self.active.fetchAdd(1, .monotonic);
    }

    pub fn decActive(self: *Upstream) void {
        _ = self.active.fetchSub(1, .monotonic);
    }
};

// ── Load balancing ────────────────────────────────────────────────────────────

pub const LoadBalancer = struct {
    upstreams: []Upstream,
    strategy: Strategy,
    rr_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(upstreams: []Upstream, strategy: Strategy) LoadBalancer {
        return .{ .upstreams = upstreams, .strategy = strategy };
    }

    pub fn pick(self: *LoadBalancer) *Upstream {
        const healthy = self.healthyUpstreams();
        if (healthy == 0) {
            const idx = self.rr_counter.fetchAdd(1, .monotonic) % self.upstreams.len;
            return &self.upstreams[idx];
        }

        return switch (self.strategy) {
            .round_robin => blk: {
                var attempts: usize = 0;
                while (attempts < self.upstreams.len) : (attempts += 1) {
                    const idx = self.rr_counter.fetchAdd(1, .monotonic) % self.upstreams.len;
                    if (self.upstreams[idx].healthy.load(.acquire)) {
                        break :blk &self.upstreams[idx];
                    }
                }
                break :blk &self.upstreams[0];
            },
            .least_connections => blk: {
                var best: *Upstream = &self.upstreams[0];
                var best_count: u32 = std.math.maxInt(u32);
                for (self.upstreams) |*u| {
                    if (!u.healthy.load(.acquire)) continue;
                    const c = u.active.load(.monotonic);
                    if (c < best_count) {
                        best_count = c;
                        best = u;
                    }
                }
                break :blk best;
            },
            // ip_hash requires the client IP — fall back to round_robin here.
            // The worker passes the hashed IP via pickWithHash() when available.
            .ip_hash => blk: {
                const idx = self.rr_counter.fetchAdd(1, .monotonic) % self.upstreams.len;
                break :blk &self.upstreams[idx];
            },
        };
    }

    fn healthyUpstreams(self: *LoadBalancer) usize {
        var n: usize = 0;
        for (self.upstreams) |u| {
            if (u.healthy.load(.acquire)) n += 1;
        }
        return n;
    }
};

// ── Per-worker idle connection pool ───────────────────────────────────────────

const IdleConn = struct {
    fd: std.posix.fd_t,
    upstream: *Upstream,
};

pub const LocalPool = struct {
    conns: []IdleConn,
    top: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !LocalPool {
        return .{ .conns = try allocator.alloc(IdleConn, capacity) };
    }

    pub fn deinit(self: *LocalPool, allocator: std.mem.Allocator) void {
        for (self.conns[0..self.top]) |c| {
            _ = linux.close(c.fd);
        }
        allocator.free(self.conns);
    }

    /// Pop an idle connection for the given upstream, or null if none.
    /// Increments upstream.active.
    pub fn pop(self: *LocalPool, upstream: *Upstream) ?std.posix.fd_t {
        var i = self.top;
        while (i > 0) {
            i -= 1;
            if (self.conns[i].upstream == upstream) {
                const fd = self.conns[i].fd;
                self.top -= 1;
                self.conns[i] = self.conns[self.top];
                upstream.incActive();
                return fd;
            }
        }
        return null;
    }

    /// Return a connection to the pool. Decrements upstream.active.
    /// Closes the fd if the pool is full or if fd is invalid (< 0).
    pub fn push(self: *LocalPool, fd: std.posix.fd_t, upstream: *Upstream) void {
        upstream.decActive();

        // Guard: never store an invalid fd
        if (fd < 0) return;

        if (self.top >= self.conns.len) {
            _ = linux.close(fd);
            return;
        }
        self.conns[self.top] = .{ .fd = fd, .upstream = upstream };
        self.top += 1;
    }
};

// ── New upstream connection ────────────────────────────────────────────────────

pub const ConnectOptions = struct {
    timeout_ms: u32 = 2000,
};

/// Create a new non-blocking TCP socket connected (or connecting) to `upstream`.
///
/// This function creates the socket, sets TCP_NODELAY, calls the non-blocking
/// posix.connect (which immediately returns WouldBlock for non-blocking sockets),
/// and returns the fd.
///
/// The caller is responsible for submitting an IORING_OP_CONNECT SQE via
/// ring.submitConnect() so that the async completion is reported. The CQE
/// will fire onConnect() with res==0 on success.
///
/// We do NOT call upstream.incActive() here — that is done by the caller in
/// onConnect() so that we don't double-count if the caller also pops from
/// the pool.
pub fn connectNew(upstream: *Upstream, opts: ConnectOptions) !std.posix.fd_t {
    _ = opts;

    const fd = try std.posix.socket(
        upstream.addr.any.family,
        std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
        0,
    );
    errdefer std.posix.close(fd);

    // TCP_NODELAY — disable Nagle's algorithm (important for proxy latency)
    const one: c_int = 1;
    _ = std.posix.setsockopt(
        fd,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&one),
    ) catch {};

    // Non-blocking connect — will get EINPROGRESS / WouldBlock immediately.
    // The actual connect completion is reported via io_uring CONNECT CQE.
    std.posix.connect(fd, &upstream.addr.any, upstream.addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {}, // expected
        else => return err,
    };

    return fd;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "local pool push/pop" {
    const allocator = std.testing.allocator;

    var up = Upstream{ .addr = try std.net.Address.parseIp4("127.0.0.1", 3000) };
    var pool = try LocalPool.init(allocator, 8);
    defer pool.deinit(allocator);

    try std.testing.expect(pool.pop(&up) == null);

    // Manually push a fake fd (bypassing active count for unit test)
    pool.conns[0] = .{ .fd = 99, .upstream = &up };
    pool.top = 1;
    _ = up.active.fetchAdd(1, .monotonic); // simulate it being active

    const fd = pool.pop(&up);
    try std.testing.expectEqual(@as(?std.posix.fd_t, 99), fd);
    try std.testing.expectEqual(@as(u32, 2), up.active.load(.monotonic)); // pop increments
}

test "pool push with invalid fd" {
    const allocator = std.testing.allocator;
    var up = Upstream{ .addr = try std.net.Address.parseIp4("127.0.0.1", 3000) };
    _ = up.active.fetchAdd(1, .monotonic);
    var pool = try LocalPool.init(allocator, 8);
    defer pool.deinit(allocator);

    // Pushing fd=-1 should not store it and should not crash
    pool.push(-1, &up);
    try std.testing.expectEqual(@as(usize, 0), pool.top);
    try std.testing.expectEqual(@as(u32, 0), up.active.load(.monotonic));
}

test "round robin load balancer" {
    var addrs = [_]Upstream{
        .{ .addr = try std.net.Address.parseIp4("127.0.0.1", 3000) },
        .{ .addr = try std.net.Address.parseIp4("127.0.0.1", 3001) },
        .{ .addr = try std.net.Address.parseIp4("127.0.0.1", 3002) },
    };
    var lb = LoadBalancer.init(&addrs, .round_robin);

    const a = lb.pick();
    const b = lb.pick();
    const c = lb.pick();
    const d = lb.pick();

    try std.testing.expect(a != b);
    try std.testing.expect(b != c);
    try std.testing.expect(a == d);
}
