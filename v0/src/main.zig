/// main.zig — zproxy entry point
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

const config_mod = @import("config.zig");
const Config = config_mod.Config;
const ServerConfig = config_mod.ServerConfig;
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

    // Accept both zproxy.toml and legacy zproxy.zon
    const config_path = if (args.len > 1) args[1] else detectConfigFile();
    const cfg = try config_mod.load(allocator, config_path);

    std.log.info("zproxy starting", .{});
    std.log.info("  config:  {s}", .{config_path});
    std.log.info("  workers: {d}", .{cfg.global.workers});
    std.log.info("  wsl2:    {}", .{build_options.wsl2});
    std.log.info("  sqpoll:  {}", .{build_options.sqpoll});
    std.log.info("  sockmap: {}", .{build_options.sockmap});
    std.log.info("  send_zc: {}", .{build_options.send_zc});
    std.log.info("  ktls:    {}", .{build_options.ktls});
    std.log.info("  servers: {d}", .{cfg.servers.len});

    // ── Build LoadBalancers — one per server block ────────────────────────────
    // Each server block can have multiple named upstream pools.
    // We build a flat ServerRuntime per server and hand it to workers.

    var server_runtimes = try allocator.alloc(ServerRuntime, cfg.servers.len);
    defer {
        for (server_runtimes) |*rt| rt.deinit(allocator);
        allocator.free(server_runtimes);
    }

    for (cfg.servers, 0..) |*srv, si| {
        server_runtimes[si] = try ServerRuntime.init(allocator, srv);
        std.log.info("  server[{d}]: {s}:{d} ({d} pools, {d} locations)", .{ si, srv.bind, srv.port, srv.upstream_pools.len, srv.locations.len });
        for (srv.server_name) |name| {
            std.log.info("    server_name: {s}", .{name});
        }
        for (srv.upstream_pools) |*pool| {
            std.log.info("    pool '{s}': {d} upstreams, strategy={s}", .{ pool.name, pool.upstreams.len, @tagName(pool.strategy) });
        }
    }

    // ── Create listen sockets — one per server block ──────────────────────────
    var listen_fds = try allocator.alloc(std.posix.fd_t, cfg.servers.len);
    defer allocator.free(listen_fds);
    defer for (listen_fds) |fd| std.posix.close(fd);

    for (cfg.servers, 0..) |*srv, i| {
        listen_fds[i] = try createListenSocket(srv);
        std.log.info("listening on {s}:{d}", .{ srv.bind, srv.port });
    }

    // ── Spawn workers ─────────────────────────────────────────────────────────
    const n_workers: u32 = if (cfg.global.workers == 0)
        @intCast(std.Thread.getCpuCount() catch 4)
    else
        cfg.global.workers;

    std.log.info("spawning {d} workers", .{n_workers});

    // Each worker handles ALL server blocks on all listen fds.
    // With SO_REUSEPORT the kernel distributes connections across workers.
    const threads = try allocator.alloc(std.Thread, n_workers);
    defer allocator.free(threads);

    for (threads, 0..) |*t, i| {
        const wcfg = worker_mod.WorkerConfig{
            .id = @intCast(i),
            .listen_fds = listen_fds,
            .cfg = &cfg,
            .server_runtimes = server_runtimes,
            .allocator = allocator,
        };
        t.* = try std.Thread.spawn(.{}, worker_mod.workerThread, .{wcfg});
    }

    std.log.info("zproxy running — press Ctrl+C to stop", .{});
    waitForSignal();

    std.log.info("shutting down...", .{});
    worker_mod.shutdown_flag.store(true, .release);
    for (listen_fds) |fd| std.posix.close(fd);
    for (threads) |t| t.join();
    std.log.info("zproxy stopped", .{});
}

// ── ServerRuntime — per-server live state ─────────────────────────────────────

/// Holds the live LoadBalancer instances for each upstream pool in a server.
pub const PoolRuntime = struct {
    name: []const u8,
    upstreams: []pool_mod.Upstream,
    lb: pool_mod.LoadBalancer,
};

pub const ServerRuntime = struct {
    server_cfg: *const ServerConfig,
    pools: []PoolRuntime,

    pub fn init(allocator: std.mem.Allocator, srv: *const ServerConfig) !ServerRuntime {
        const pools = try allocator.alloc(PoolRuntime, srv.upstream_pools.len);
        errdefer allocator.free(pools);

        for (srv.upstream_pools, 0..) |*pool_cfg, i| {
            const upstreams = try allocator.alloc(pool_mod.Upstream, pool_cfg.upstreams.len);
            errdefer allocator.free(upstreams);

            for (pool_cfg.upstreams, 0..) |entry, j| {
                const addr = parseAddr(entry.addr) catch |err| {
                    std.log.err("invalid upstream '{s}' in pool '{s}': {}", .{ entry.addr, pool_cfg.name, err });
                    return err;
                };
                upstreams[j] = pool_mod.Upstream{
                    .addr = addr,
                };
            }

            pools[i] = PoolRuntime{
                .name = pool_cfg.name,
                .upstreams = upstreams,
                .lb = pool_mod.LoadBalancer.init(upstreams, pool_cfg.strategy),
            };
        }

        return ServerRuntime{ .server_cfg = srv, .pools = pools };
    }

    pub fn deinit(self: *ServerRuntime, allocator: std.mem.Allocator) void {
        for (self.pools) |*p| allocator.free(p.upstreams);
        allocator.free(self.pools);
    }

    /// Find a pool by name. Returns null if not found.
    pub fn findPool(self: *ServerRuntime, name: []const u8) ?*PoolRuntime {
        for (self.pools) |*p| {
            if (std.mem.eql(u8, p.name, name)) return p;
        }
        return null;
    }
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn detectConfigFile() []const u8 {
    // Prefer zproxy.toml, fall back to legacy zproxy.zon
    std.fs.cwd().access("zproxy.toml", .{}) catch {
        return "zproxy.zon";
    };
    return "zproxy.toml";
}

fn createListenSocket(srv: *const ServerConfig) !std.posix.fd_t {
    const addr_str = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "{s}:{d}",
        .{ srv.bind, srv.port },
    );
    defer std.heap.page_allocator.free(addr_str);
    const addr = try parseAddr(addr_str);

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
    try std.posix.listen(fd, @intCast(srv.backlog));

    return fd;
}

pub fn parseAddr(s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidAddress;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);
    return std.net.Address.resolveIp(host, port) catch
        std.net.Address.parseIp(host, port);
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
