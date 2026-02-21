/// main.zig — zproxy entry point
///
/// 1. Parse CLI args / load config
/// 2. Create listening socket with SO_REUSEPORT
/// 3. Spawn one worker thread per CPU core (or cfg.workers)
/// 4. Wait for SIGINT/SIGTERM and drain gracefully
const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const build_options = @import("build_options");

const Config = @import("config.zig").Config;
const worker_mod = @import("worker.zig");
const pool_mod = @import("upstream/pool.zig");

// Re-export sub-modules so `zig test src/main.zig` runs all tests
pub const io_ring = @import("io/ring.zig");
pub const http_parser = @import("http/parser.zig");
pub const upstream_pool = @import("upstream/pool.zig");
pub const config = @import("config.zig");

// ── Logging ───────────────────────────────────────────────────────────────────

pub const std_options = std.Options{
    .log_level = .debug, // overridden at runtime by cfg.log_level
};

// ── Main ──────────────────────────────────────────────────────────────────────

pub fn main() !void {
    // Allocator: SmpAllocator for multi-threaded perf (new in Zig 0.14)
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── Config ─────────────────────────────────────────────────────────────
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config_path = if (args.len > 1) args[1] else "zproxy.zon";
    const cfg = try @import("config.zig").load(allocator, config_path);

    std.log.info("zproxy starting", .{});
    std.log.info("  bind:    {s}:{d}", .{ cfg.bind, cfg.port });
    std.log.info("  wsl2:    {}", .{build_options.wsl2});
    std.log.info("  sqpoll:  {}", .{build_options.sqpoll});
    std.log.info("  sockmap: {}", .{build_options.sockmap});
    std.log.info("  send_zc: {}", .{build_options.send_zc});
    std.log.info("  ktls:    {}", .{build_options.ktls});

    // ── Upstream pool ──────────────────────────────────────────────────────
    const upstream_addrs = cfg.upstream.addrs;
    var upstreams = try allocator.alloc(pool_mod.Upstream, upstream_addrs.len);
    defer allocator.free(upstreams);

    for (upstream_addrs, 0..) |addr_str, i| {
        const addr = parseAddr(addr_str) catch |err| {
            std.log.err("invalid upstream address '{s}': {}", .{ addr_str, err });
            return err;
        };
        upstreams[i] = pool_mod.Upstream{ .addr = addr };
        std.log.info("  upstream[{d}]: {}", .{ i, addr });
    }

    var lb = pool_mod.LoadBalancer.init(upstreams, .round_robin);

    // ── Listening socket ───────────────────────────────────────────────────
    const listen_fd = try createListenSocket(cfg);
    defer std.posix.close(listen_fd);
    std.log.info("listening on {s}:{d}", .{ cfg.bind, cfg.port });

    // ── Worker threads ─────────────────────────────────────────────────────
    const n_workers = if (cfg.workers == 0)
        @as(u32, @intCast(std.Thread.getCpuCount() catch 4))
    else
        cfg.workers;

    std.log.info("spawning {d} workers", .{n_workers});

    const threads = try allocator.alloc(std.Thread, n_workers);
    defer allocator.free(threads);

    for (threads, 0..) |*t, i| {
        const wcfg = worker_mod.WorkerConfig{
            .id = @intCast(i),
            .listen_fd = listen_fd,
            .cfg = &cfg,
            .lb = &lb,
            .allocator = allocator,
        };

        t.* = try std.Thread.spawn(.{}, worker_mod.workerThread, .{wcfg});

        // Pin thread to CPU core (NUMA-aware on native Linux)
        if (!build_options.wsl2) {
            pinThreadToCore(t.*, @intCast(i)) catch |err| {
                std.log.warn("could not pin worker {d} to core: {}", .{ i, err });
            };
        }
    }

    // ── Wait for signal ────────────────────────────────────────────────────
    std.log.info("zproxy running — press Ctrl+C to stop", .{});
    waitForSignal();

    std.log.info("shutting down...", .{});
    // Workers will drain naturally when the listen socket closes
    for (threads) |t| t.join();
    std.log.info("zproxy stopped", .{});
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn createListenSocket(cfg: Config) !std.posix.fd_t {
    const addr = try parseAddr(try std.fmt.allocPrint(
        std.heap.page_allocator,
        "{s}:{d}",
        .{ cfg.bind, cfg.port },
    ));

    const fd = try std.posix.socket(
        addr.any.family,
        std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
        0,
    );
    errdefer std.posix.close(fd);

    // SO_REUSEADDR — allow fast restart without TIME_WAIT
    const one: c_int = 1;
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one));

    // SO_REUSEPORT — kernel load-balances connections across all workers
    // Each worker gets its own socket on the same port. No thundering herd.
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one));

    try std.posix.bind(fd, &addr.any, addr.getOsSockLen());
    try std.posix.listen(fd, @intCast(cfg.backlog));

    return fd;
}

/// Parse "host:port" or "ip:port" into a std.net.Address.
fn parseAddr(s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidAddress;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);
    return std.net.Address.resolveIp(host, port) catch
        std.net.Address.parseIp(host, port);
}

/// Pin a thread to a specific CPU core via sched_setaffinity.
fn pinThreadToCore(thread: std.Thread, core: u32) !void {
    var cpuset = std.mem.zeroes(linux.cpu_set_t);
    linux.CPU_SET(core % 1024, &cpuset);
    const tid = thread.impl.handle; // pthreads tid
    const rc = linux.sched_setaffinity(
        @intCast(tid),
        @sizeOf(linux.cpu_set_t),
        &cpuset,
    );
    if (rc != 0) return error.SetAffinityFailed;
}

/// Block until SIGINT or SIGTERM.
fn waitForSignal() void {
    var sa = std.posix.Sigaction{
        .handler = .{ .handler = handleSig },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    // Suspend main thread
    while (!got_signal) {
        std.time.sleep(100 * std.time.ns_per_ms);
    }
}

var got_signal: bool = false;

fn handleSig(_: c_int) callconv(.C) void {
    got_signal = true;
}
