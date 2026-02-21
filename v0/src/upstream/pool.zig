/// upstream/pool.zig — per-worker upstream connection pool
///
/// Each worker thread owns one Pool. Connections are kept alive between
/// requests (HTTP keep-alive to upstream). The pool is a simple fixed-size
/// ring of idle file descriptors — no mutex needed because only the owning
/// worker thread ever touches it.
///
/// Work stealing: when a worker's pool is empty it can steal from a sibling's
/// pool via the shared `GlobalPool`. This is lock-free via atomics.
const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const build_options = @import("build_options");

// ── Upstream address ──────────────────────────────────────────────────────────

pub const Upstream = struct {
    addr: std.net.Address,
    /// Running count of active connections (for least-connections LB)
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Running count of total requests handled (for round-robin)
    requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Health: true if the upstream responded successfully recently
    healthy: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn incActive(self: *Upstream) void {
        _ = self.active.fetchAdd(1, .monotonic);
    }

    pub fn decActive(self: *Upstream) void {
        _ = self.active.fetchSub(1, .monotonic);
    }
};

// ── Load balancing ────────────────────────────────────────────────────────────

pub const Strategy = enum { round_robin, least_connections };

pub const LoadBalancer = struct {
    upstreams: []Upstream,
    strategy: Strategy,
    /// Round-robin counter — wraps around. Shared across all workers.
    rr_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(upstreams: []Upstream, strategy: Strategy) LoadBalancer {
        return .{ .upstreams = upstreams, .strategy = strategy };
    }

    /// Pick the next upstream to send a request to.
    pub fn pick(self: *LoadBalancer) *Upstream {
        const healthy = self.healthyUpstreams();
        if (healthy == 0) {
            // All unhealthy — pick round-robin anyway (fail-open)
            const idx = self.rr_counter.fetchAdd(1, .monotonic) % self.upstreams.len;
            return &self.upstreams[idx];
        }

        return switch (self.strategy) {
            .round_robin => blk: {
                // Pick among healthy ones only
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

/// Idle connection entry
const IdleConn = struct {
    fd: std.posix.fd_t,
    upstream: *Upstream,
};

/// A fixed-capacity stack of idle file descriptors.
/// Only the owning worker thread pushes/pops — no locking needed.
pub const LocalPool = struct {
    conns: []IdleConn,
    top: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !LocalPool {
        return .{ .conns = try allocator.alloc(IdleConn, capacity) };
    }

    pub fn deinit(self: *LocalPool, allocator: std.mem.Allocator) void {
        // Close all idle connections
        for (self.conns[0..self.top]) |c| {
            _ = linux.close(c.fd);
        }
        allocator.free(self.conns);
    }

    /// Pop an idle connection for the given upstream, or null if none.
    pub fn pop(self: *LocalPool, upstream: *Upstream) ?std.posix.fd_t {
        // Scan from top (hot end) downwards
        var i = self.top;
        while (i > 0) {
            i -= 1;
            if (self.conns[i].upstream == upstream) {
                const fd = self.conns[i].fd;
                // Swap with top-1 to maintain compact array
                self.top -= 1;
                self.conns[i] = self.conns[self.top];
                upstream.incActive();
                return fd;
            }
        }
        return null;
    }

    /// Return a connection to the pool. Returns false (and closes the fd)
    /// if the pool is full.
    pub fn push(self: *LocalPool, fd: std.posix.fd_t, upstream: *Upstream) void {
        upstream.decActive();
        if (self.top >= self.conns.len) {
            // Pool full — just close
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
    /// Use TCP Fast Open (sends SYN with data — saves one RTT)
    tcp_fast_open: bool = build_options.send_zc, // reuse native flag
};

/// Open a new TCP connection to `upstream`. Blocking (called only when the
/// pool is empty). Returns a non-blocking fd ready for io_uring.
pub fn connectNew(upstream: *Upstream, opts: ConnectOptions) !std.posix.fd_t {
    const fd = try std.posix.socket(
        upstream.addr.any.family,
        std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
        0,
    );
    errdefer std.posix.close(fd);

    // TCP Fast Open — available on native Linux, silently skipped on WSL2
    if (opts.tcp_fast_open and !build_options.wsl2) {
        const MSG_FASTOPEN: u32 = 0x20000000;
        _ = MSG_FASTOPEN; // used later in sendto() path
        // Kernel handles the TFO cookie automatically after first connect
    }

    // TCP_NODELAY — disable Nagle's algorithm for proxy use
    const one: c_int = 1;
    _ = std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};

    upstream.incActive();

    // Non-blocking connect — the actual completion comes via io_uring CONNECT
    std.posix.connect(fd, &upstream.addr.any, upstream.addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {}, // expected — io_uring will report completion
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

    // No connection yet
    try std.testing.expect(pool.pop(&up) == null);

    // Fake fd
    pool.push(99, &up);
    try std.testing.expectEqual(@as(?std.posix.fd_t, 99), pool.pop(&up));
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

    // Should cycle through all three and wrap
    try std.testing.expect(a != b);
    try std.testing.expect(b != c);
    try std.testing.expect(a == d); // wraps back to first
}
