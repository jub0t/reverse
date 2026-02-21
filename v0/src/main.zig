/// main.zig — zproxy entry point
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

const Config = @import("config.zig").Config;
const worker_mod = @import("worker.zig");
const pool_mod = @import("upstream/pool.zig");

pub const io_ring = @import("io/ring.zig");
pub const http_parser = @import("http/parser.zig");
pub const upstream_pool = @import("upstream/pool.zig");
pub const config = @import("config.zig");

pub const std_options = std.Options{
    .log_level = .debug,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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

    const listen_fd = try createListenSocket(cfg);
    std.log.info("listening on {s}:{d}", .{ cfg.bind, cfg.port });

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

        if (!build_options.wsl2) {
            pinThreadToCore(t.*, @intCast(i)) catch |err| {
                std.log.warn("could not pin worker {d} to core: {}", .{ i, err });
            };
        }
    }

    std.log.info("zproxy running — press Ctrl+C to stop", .{});
    waitForSignal();

    std.log.info("shutting down...", .{});

    // Signal workers to stop via atomic flag — workers check this every 100ms
    // via a recurring TIMEOUT SQE, so no tkill or pthread internals needed.
    worker_mod.shutdown_flag.store(true, .release);

    // Close listen socket so no new connections are accepted
    std.posix.close(listen_fd);

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

    const one: c_int = 1;
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one));
    try std.posix.bind(fd, &addr.any, addr.getOsSockLen());
    try std.posix.listen(fd, @intCast(cfg.backlog));

    return fd;
}

fn parseAddr(s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidAddress;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);
    return std.net.Address.resolveIp(host, port) catch
        std.net.Address.parseIp(host, port);
}

fn pinThreadToCore(thread: std.Thread, core: u32) !void {
    var cpuset = std.mem.zeroes(linux.cpu_set_t);
    linux.CPU_SET(core % 1024, &cpuset);
    const tid = thread.impl.thread.parent_tid;
    const rc = linux.sched_setaffinity(
        @intCast(tid),
        @sizeOf(linux.cpu_set_t),
        &cpuset,
    );
    if (rc != 0) return error.SetAffinityFailed;
}

// ── Signal handling ───────────────────────────────────────────────────────────

var got_signal = std.atomic.Value(bool).init(false);

fn handleSig(_: c_int) callconv(.C) void {
    got_signal.store(true, .release);
}

fn waitForSignal() void {
    var sa = std.posix.Sigaction{
        .handler = .{ .handler = handleSig },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    while (!got_signal.load(.acquire)) {
        std.time.sleep(100 * std.time.ns_per_ms);
    }
}
