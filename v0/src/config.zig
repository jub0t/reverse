/// config.zig — Runtime configuration loaded from zproxy.zon
///
/// Example config file:
///
///   .{
///       .bind = "0.0.0.0",
///       .port = 8080,
///       .workers = 0,          // 0 = auto (one per logical CPU)
///       .backlog = 4096,
///       .upstream = .{
///           .addrs = .{ "127.0.0.1:3000", "127.0.0.1:3001" },
///           .strategy = .round_robin,
///           .pool_size = 64,
///           .connect_timeout_ms = 2000,
///           .keepalive = true,
///       },
///       .log_level = .info,
///   }
const std = @import("std");

pub const LoadBalanceStrategy = enum {
    round_robin,
    least_connections,
    random,
};

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const UpstreamConfig = struct {
    /// upstream addresses: "host:port"
    addrs: []const []const u8,
    strategy: LoadBalanceStrategy = .round_robin,
    /// max idle keepalive connections per upstream per worker thread
    pool_size: u32 = 64,
    connect_timeout_ms: u32 = 2000,
    keepalive: bool = true,
    /// TCP Fast Open to upstreams (native Linux only)
    tcp_fast_open: bool = true,
    /// health check interval in milliseconds; 0 = disabled
    health_check_interval_ms: u32 = 5000,
};

pub const Config = struct {
    bind: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    /// 0 = one worker per logical CPU
    workers: u32 = 0,
    backlog: u32 = 4096,
    /// io_uring submission queue depth per worker
    io_uring_sq_depth: u32 = 4096,
    /// number of provided buffers in the kernel buffer ring per worker
    io_uring_buf_count: u32 = 1024,
    /// size of each provided buffer (bytes)
    io_uring_buf_size: u32 = 32768,
    upstream: UpstreamConfig,
    log_level: LogLevel = .info,
};

/// Defaults used when no config file is found — handy for quick local testing.
pub const default_upstream = UpstreamConfig{
    .addrs = &.{"127.0.0.1:3000"},
};

pub const default_config = Config{
    .upstream = default_upstream,
};

/// Load config from a ZON file path, falling back to defaults on error.
/// Caller owns the returned memory (use a long-lived allocator like the
/// process GPA).
pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            std.log.warn("config file '{s}' not found — using defaults", .{path});
            return default_config;
        }
        return err;
    };
    defer file.close();

    const src = try file.readToEndAlloc(allocator, 1 << 20); // 1 MB max
    defer allocator.free(src);

    // TODO: parse ZON properly. For now we return defaults so the binary
    // boots and the io_uring loop can be developed & tested immediately.
    // Replace with std.zon.parseFromSlice when the API stabilises in 0.14.

    std.log.info("config loaded from '{s}' (ZON parser TODO)", .{path});
    return default_config;
}

test "default config is valid" {
    const cfg = default_config;
    try std.testing.expect(cfg.port > 0);
    try std.testing.expect(cfg.upstream.addrs.len > 0);
}
