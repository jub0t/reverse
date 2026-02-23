/// config.zig — zproxy runtime configuration
///
/// Loads from a TOML file (default: zproxy.toml).
/// Falls back to built-in defaults if the file is not found.
///
/// See zproxy.toml.example for the full annotated format.
const std = @import("std");
const toml = @import("toml.zig");

// ── Enums ─────────────────────────────────────────────────────────────────────

pub const Strategy = enum {
    round_robin,
    least_connections,
    ip_hash,

    pub fn fromString(s: []const u8) !Strategy {
        if (std.mem.eql(u8, s, "round_robin")) return .round_robin;
        if (std.mem.eql(u8, s, "least_connections")) return .least_connections;
        if (std.mem.eql(u8, s, "ip_hash")) return .ip_hash;
        return error.InvalidStrategy;
    }
};

pub const MatchType = enum {
    prefix,
    exact,
    regex,

    pub fn fromString(s: []const u8) !MatchType {
        if (std.mem.eql(u8, s, "prefix")) return .prefix;
        if (std.mem.eql(u8, s, "exact")) return .exact;
        if (std.mem.eql(u8, s, "regex")) return .regex;
        return error.InvalidMatchType;
    }
};

pub const RateLimitStrategy = enum {
    token_bucket,
    sliding_window,

    pub fn fromString(s: []const u8) !RateLimitStrategy {
        if (std.mem.eql(u8, s, "token_bucket")) return .token_bucket;
        if (std.mem.eql(u8, s, "sliding_window")) return .sliding_window;
        return error.InvalidRateLimitStrategy;
    }
};

pub const LogLevel = enum { debug, info, warn, err };

// ── Sub-configs ───────────────────────────────────────────────────────────────

pub const UpstreamEntry = struct {
    /// "host:port"
    addr: []const u8,
    /// Relative weight for weighted round-robin (default 10)
    weight: u32 = 10,
    /// Max concurrent connections to this upstream (0 = unlimited)
    max_conns: u32 = 0,
};

pub const HealthCheckConfig = struct {
    enabled: bool = true,
    interval_ms: u32 = 5000,
    timeout_ms: u32 = 2000,
    /// HTTP path to GET for health check
    path: []const u8 = "/",
};

pub const UpstreamPoolConfig = struct {
    /// Name referenced by LocationConfig.upstream_pool
    name: []const u8,
    strategy: Strategy = .round_robin,
    pool_size: u32 = 64,
    upstreams: []UpstreamEntry,
    health_check: HealthCheckConfig = .{},
};

pub const RateLimitConfig = struct {
    requests_per_second: u32 = 100,
    /// Token bucket burst size
    burst: u32 = 200,
    strategy: RateLimitStrategy = .token_bucket,
};

/// A single header add/remove rule.
pub const HeaderRule = struct {
    name: []const u8,
    /// Value string; may contain variables: $remote_addr, $host, $request_id
    /// Empty string for remove rules.
    value: []const u8 = "",
};

pub const StaticConfig = struct {
    /// Filesystem root to serve files from
    root: []const u8,
    /// If true and file not found, proxy to upstream_pool instead of 404
    fallback: bool = false,
};

pub const LocationConfig = struct {
    /// URI prefix/path to match
    match: []const u8,
    match_type: MatchType = .prefix,
    /// Name of the upstream pool to proxy to (must exist in server.upstream_pools)
    upstream_pool: []const u8 = "",

    rate_limit: ?RateLimitConfig = null,

    /// Headers to add/overwrite on the proxied request to upstream
    add_request_header: []HeaderRule = &.{},
    /// Headers to strip from the proxied request to upstream
    remove_request_header: []HeaderRule = &.{},
    /// Headers to add/overwrite on the response back to the client
    add_response_header: []HeaderRule = &.{},
    /// Headers to strip from the response back to the client
    remove_response_header: []HeaderRule = &.{},

    /// Non-null = serve files from disk for this location
    static: ?StaticConfig = null,
};

pub const TimeoutConfig = struct {
    connect_ms: u32 = 2000,
    read_ms: u32 = 30000,
    write_ms: u32 = 30000,
    keepalive_ms: u32 = 75000,
};

pub const ServerConfig = struct {
    bind: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    backlog: u32 = 4096,
    /// Virtual host names matched against the HTTP Host header.
    /// Empty slice = match all.
    server_name: [][]const u8 = &.{},
    upstream_pools: []UpstreamPoolConfig,
    locations: []LocationConfig = &.{},
    timeouts: TimeoutConfig = .{},
    /// Path to TLS certificate chain (PEM). Null = plaintext.
    tls_cert: ?[]const u8 = null,
    /// Path to TLS private key (PEM). Null = plaintext.
    tls_key: ?[]const u8 = null,
};

/// Global settings that apply to the whole process.
pub const GlobalConfig = struct {
    /// 0 = one worker per logical CPU
    workers: u32 = 0,
    log_level: LogLevel = .info,
    io_uring_sq_depth: u32 = 4096,
    io_uring_buf_count: u32 = 1024,
    io_uring_buf_size: u32 = 32768,
};

/// Top-level config — one per process.
pub const Config = struct {
    global: GlobalConfig,
    servers: []ServerConfig,

    // Legacy flat accessors used by existing main.zig / worker.zig call sites.
    // These read from the FIRST server block so old code compiles unchanged.

    pub fn bind(self: *const Config) []const u8 {
        if (self.servers.len > 0) return self.servers[0].bind;
        return "0.0.0.0";
    }
    pub fn port(self: *const Config) u16 {
        if (self.servers.len > 0) return self.servers[0].port;
        return 8080;
    }
    pub fn backlog(self: *const Config) u32 {
        if (self.servers.len > 0) return self.servers[0].backlog;
        return 4096;
    }
    pub fn workers(self: *const Config) u32 {
        return self.global.workers;
    }

    // io_uring fields accessed directly in WorkerConfig
    pub fn io_uring_sq_depth(self: *const Config) u32 {
        return self.global.io_uring_sq_depth;
    }
    pub fn io_uring_buf_count(self: *const Config) u32 {
        return self.global.io_uring_buf_count;
    }
    pub fn io_uring_buf_size(self: *const Config) u32 {
        return self.global.io_uring_buf_size;
    }
};

// ── Defaults ──────────────────────────────────────────────────────────────────

const default_upstream_entry = UpstreamEntry{ .addr = "127.0.0.1:3000" };

const default_upstream_pool = UpstreamPoolConfig{
    .name = "default",
    .upstreams = @constCast(&[_]UpstreamEntry{default_upstream_entry}),
};

const default_location = LocationConfig{
    .match = "/",
    .upstream_pool = "default",
};

const default_server = ServerConfig{
    .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
    .locations = @constCast(&[_]LocationConfig{default_location}),
};

pub const default_config = Config{
    .global = .{},
    .servers = @constCast(&[_]ServerConfig{default_server}),
};

// ── TOML loader ───────────────────────────────────────────────────────────────

pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            std.log.warn("config '{s}' not found — using defaults", .{path});
            return default_config;
        }
        return err;
    };
    defer file.close();

    const src = try file.readToEndAlloc(allocator, 4 << 20); // 4 MB max
    defer allocator.free(src);

    var doc = toml.parse(allocator, src) catch |err| {
        std.log.err("TOML parse error in '{s}': {}", .{ path, err });
        return err;
    };
    defer doc.deinit();

    return fromDoc(allocator, &doc);
}

// ── Build Config from parsed Document ────────────────────────────────────────

fn fromDoc(allocator: std.mem.Allocator, doc: *const toml.Document) !Config {
    const global = try readGlobal(doc);
    const servers = try readServers(allocator, doc);
    return Config{ .global = global, .servers = servers };
}

fn readGlobal(doc: *const toml.Document) !GlobalConfig {
    var g = GlobalConfig{};
    if (doc.getInt("global.workers")) |v| g.workers = @intCast(v);
    if (doc.getInt("global.io_uring_sq_depth")) |v| g.io_uring_sq_depth = @intCast(v);
    if (doc.getInt("global.io_uring_buf_count")) |v| g.io_uring_buf_count = @intCast(v);
    if (doc.getInt("global.io_uring_buf_size")) |v| g.io_uring_buf_size = @intCast(v);
    if (doc.getString("global.log_level")) |s| {
        g.log_level = parseLogLevel(s);
    }
    return g;
}

fn readServers(allocator: std.mem.Allocator, doc: *const toml.Document) ![]ServerConfig {
    const n = doc.arrayLen("server");
    if (n == 0) {
        // No [[server]] blocks — try reading a flat single-server format
        // (backwards compat with old zproxy.zon style)
        const single = try readSingleServer(allocator, doc) orelse {
            std.log.warn("no [[server]] blocks found — using defaults", .{});
            return allocator.dupe(ServerConfig, &[_]ServerConfig{default_server});
        };
        const slice = try allocator.alloc(ServerConfig, 1);
        slice[0] = single;
        return slice;
    }

    const servers = try allocator.alloc(ServerConfig, n);
    errdefer allocator.free(servers);

    for (0..n) |i| {
        servers[i] = try readServer(allocator, doc, i);
    }
    return servers;
}

fn readSingleServer(allocator: std.mem.Allocator, doc: *const toml.Document) !?ServerConfig {
    // Check for a [server] table (not array)
    const port_val = doc.getInt("server.port") orelse return null;
    var s = ServerConfig{
        .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
        .locations = @constCast(&[_]LocationConfig{default_location}),
    };
    s.port = @intCast(port_val);
    if (doc.getString("server.bind")) |v| s.bind = try allocator.dupe(u8, v);
    if (doc.getInt("server.backlog")) |v| s.backlog = @intCast(v);
    s.upstream_pools = try readUpstreamPools(allocator, doc, "server");
    s.locations = try readLocations(allocator, doc, "server");
    return s;
}

fn readServer(allocator: std.mem.Allocator, doc: *const toml.Document, idx: usize) !ServerConfig {
    var buf: [128]u8 = undefined;
    const base = try std.fmt.bufPrint(&buf, "server[{d}]", .{idx});

    var s = ServerConfig{
        .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
        .locations = @constCast(&[_]LocationConfig{default_location}),
    };

    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.bind", .{base}))) |v| {
        s.bind = try allocator.dupe(u8, v);
    }
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.port", .{base}))) |v| {
        s.port = @intCast(v);
    }
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.backlog", .{base}))) |v| {
        s.backlog = @intCast(v);
    }

    // server_name = ["example.com", "www.example.com"]
    const sn_key = try std.fmt.allocPrint(allocator, "{s}.server_name", .{base});
    defer allocator.free(sn_key);
    const sn_count = doc.arrayLen(sn_key);
    if (sn_count > 0) {
        const names = try allocator.alloc([]const u8, sn_count);
        for (0..sn_count) |j| {
            const k = try std.fmt.allocPrint(allocator, "{s}.server_name[{d}]", .{ base, j });
            defer allocator.free(k);
            names[j] = try allocator.dupe(u8, doc.getString(k) orelse "");
        }
        s.server_name = names;
    }

    s.upstream_pools = try readUpstreamPools(allocator, doc, base);
    s.locations = try readLocations(allocator, doc, base);
    s.timeouts = try readTimeouts(doc, base, allocator);

    // TLS cert/key paths
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.tls_cert", .{base}))) |v|
        s.tls_cert = try allocator.dupe(u8, v);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.tls_key", .{base}))) |v|
        s.tls_key = try allocator.dupe(u8, v);

    return s;
}

fn readUpstreamPools(allocator: std.mem.Allocator, doc: *const toml.Document, base: []const u8) ![]UpstreamPoolConfig {
    const key = try std.fmt.allocPrint(allocator, "{s}.upstream_pool", .{base});
    defer allocator.free(key);
    const n = doc.arrayLen(key);
    if (n == 0) return allocator.dupe(UpstreamPoolConfig, &[_]UpstreamPoolConfig{default_upstream_pool});

    const pools = try allocator.alloc(UpstreamPoolConfig, n);
    for (0..n) |i| {
        pools[i] = try readUpstreamPool(allocator, doc, base, i);
    }
    return pools;
}

fn readUpstreamPool(allocator: std.mem.Allocator, doc: *const toml.Document, base: []const u8, idx: usize) !UpstreamPoolConfig {
    const pfx = try std.fmt.allocPrint(allocator, "{s}.upstream_pool[{d}]", .{ base, idx });
    defer allocator.free(pfx);

    var pool = UpstreamPoolConfig{
        .name = "default",
        .upstreams = &.{},
    };

    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.name", .{pfx}))) |v| pool.name = try allocator.dupe(u8, v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.pool_size", .{pfx}))) |v| pool.pool_size = @intCast(v);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.strategy", .{pfx}))) |v| pool.strategy = Strategy.fromString(v) catch .round_robin;

    // health_check sub-table
    const hc_pfx = try std.fmt.allocPrint(allocator, "{s}.health_check", .{pfx});
    defer allocator.free(hc_pfx);
    pool.health_check = try readHealthCheck(doc, hc_pfx, allocator);

    // [[upstream_pool.upstream]] entries
    const up_key = try std.fmt.allocPrint(allocator, "{s}.upstream", .{pfx});
    defer allocator.free(up_key);
    const up_n = doc.arrayLen(up_key);
    if (up_n > 0) {
        const entries = try allocator.alloc(UpstreamEntry, up_n);
        for (0..up_n) |i| {
            entries[i] = try readUpstreamEntry(allocator, doc, pfx, i);
        }
        pool.upstreams = entries;
    } else {
        pool.upstreams = try allocator.dupe(UpstreamEntry, &[_]UpstreamEntry{default_upstream_entry});
    }

    return pool;
}

fn readUpstreamEntry(allocator: std.mem.Allocator, doc: *const toml.Document, pool_pfx: []const u8, idx: usize) !UpstreamEntry {
    const pfx = try std.fmt.allocPrint(allocator, "{s}.upstream[{d}]", .{ pool_pfx, idx });
    defer allocator.free(pfx);

    var e = UpstreamEntry{ .addr = "127.0.0.1:3000" };
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.addr", .{pfx}))) |v| e.addr = try allocator.dupe(u8, v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.weight", .{pfx}))) |v| e.weight = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.max_conns", .{pfx}))) |v| e.max_conns = @intCast(v);
    return e;
}

fn readHealthCheck(doc: *const toml.Document, pfx: []const u8, allocator: std.mem.Allocator) !HealthCheckConfig {
    var hc = HealthCheckConfig{};
    if (doc.getBool(try std.fmt.allocPrint(allocator, "{s}.enabled", .{pfx}))) |v| hc.enabled = v;
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.interval_ms", .{pfx}))) |v| hc.interval_ms = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.timeout_ms", .{pfx}))) |v| hc.timeout_ms = @intCast(v);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.path", .{pfx}))) |v| hc.path = try allocator.dupe(u8, v);
    return hc;
}

fn readLocations(allocator: std.mem.Allocator, doc: *const toml.Document, base: []const u8) ![]LocationConfig {
    const key = try std.fmt.allocPrint(allocator, "{s}.location", .{base});
    defer allocator.free(key);
    const n = doc.arrayLen(key);
    if (n == 0) return allocator.dupe(LocationConfig, &[_]LocationConfig{default_location});

    const locs = try allocator.alloc(LocationConfig, n);
    for (0..n) |i| {
        locs[i] = try readLocation(allocator, doc, base, i);
    }
    return locs;
}

fn readLocation(allocator: std.mem.Allocator, doc: *const toml.Document, base: []const u8, idx: usize) !LocationConfig {
    const pfx = try std.fmt.allocPrint(allocator, "{s}.location[{d}]", .{ base, idx });
    defer allocator.free(pfx);

    var loc = LocationConfig{ .match = "/" };

    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.match", .{pfx}))) |v| loc.match = try allocator.dupe(u8, v);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.match_type", .{pfx}))) |v| loc.match_type = MatchType.fromString(v) catch .prefix;
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.upstream_pool", .{pfx}))) |v| loc.upstream_pool = try allocator.dupe(u8, v);

    // rate_limit sub-table
    const rl_pfx = try std.fmt.allocPrint(allocator, "{s}.rate_limit", .{pfx});
    defer allocator.free(rl_pfx);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.requests_per_second", .{rl_pfx}))) |_| {
        loc.rate_limit = try readRateLimit(doc, rl_pfx, allocator);
    }

    // static sub-table
    const st_pfx = try std.fmt.allocPrint(allocator, "{s}.static", .{pfx});
    defer allocator.free(st_pfx);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.root", .{st_pfx}))) |root| {
        var sc = StaticConfig{ .root = try allocator.dupe(u8, root) };
        if (doc.getBool(try std.fmt.allocPrint(allocator, "{s}.fallback", .{st_pfx}))) |v| sc.fallback = v;
        loc.static = sc;
    }

    // header rules
    loc.add_request_header = try readHeaderRules(allocator, doc, pfx, "add_request_header");
    loc.remove_request_header = try readHeaderRules(allocator, doc, pfx, "remove_request_header");
    loc.add_response_header = try readHeaderRules(allocator, doc, pfx, "add_response_header");
    loc.remove_response_header = try readHeaderRules(allocator, doc, pfx, "remove_response_header");

    return loc;
}

fn readRateLimit(doc: *const toml.Document, pfx: []const u8, allocator: std.mem.Allocator) !RateLimitConfig {
    var rl = RateLimitConfig{};
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.requests_per_second", .{pfx}))) |v| rl.requests_per_second = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.burst", .{pfx}))) |v| rl.burst = @intCast(v);
    if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.strategy", .{pfx}))) |v| rl.strategy = RateLimitStrategy.fromString(v) catch .token_bucket;
    return rl;
}

fn readHeaderRules(allocator: std.mem.Allocator, doc: *const toml.Document, loc_pfx: []const u8, field: []const u8) ![]HeaderRule {
    const key = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ loc_pfx, field });
    defer allocator.free(key);
    const n = doc.arrayLen(key);
    if (n == 0) return &.{};

    const rules = try allocator.alloc(HeaderRule, n);
    for (0..n) |i| {
        const pk = try std.fmt.allocPrint(allocator, "{s}.{s}[{d}]", .{ loc_pfx, field, i });
        defer allocator.free(pk);
        var rule = HeaderRule{ .name = "" };
        if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.name", .{pk}))) |v| rule.name = try allocator.dupe(u8, v);
        if (doc.getString(try std.fmt.allocPrint(allocator, "{s}.value", .{pk}))) |v| rule.value = try allocator.dupe(u8, v);
        rules[i] = rule;
    }
    return rules;
}

fn readTimeouts(doc: *const toml.Document, base: []const u8, allocator: std.mem.Allocator) !TimeoutConfig {
    var t = TimeoutConfig{};
    const pfx = try std.fmt.allocPrint(allocator, "{s}.timeouts", .{base});
    defer allocator.free(pfx);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.connect_ms", .{pfx}))) |v| t.connect_ms = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.read_ms", .{pfx}))) |v| t.read_ms = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.write_ms", .{pfx}))) |v| t.write_ms = @intCast(v);
    if (doc.getInt(try std.fmt.allocPrint(allocator, "{s}.keepalive_ms", .{pfx}))) |v| t.keepalive_ms = @intCast(v);
    return t;
}

fn parseLogLevel(s: []const u8) LogLevel {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "warn")) return .warn;
    if (std.mem.eql(u8, s, "error") or std.mem.eql(u8, s, "err")) return .err;
    return .info;
}

// ── Route matching ────────────────────────────────────────────────────────────

/// Find the best matching location for a given path within a server.
/// Longer prefix wins; exact beats prefix.
pub fn matchLocation(server: *const ServerConfig, path: []const u8) ?*const LocationConfig {
    var best: ?*const LocationConfig = null;
    var best_len: usize = 0;

    for (server.locations) |*loc| {
        switch (loc.match_type) {
            .exact => {
                if (std.mem.eql(u8, loc.match, path)) return loc;
            },
            .prefix => {
                if (std.mem.startsWith(u8, path, loc.match)) {
                    if (loc.match.len > best_len) {
                        best = loc;
                        best_len = loc.match.len;
                    }
                }
            },
            .regex => {
                // TODO: regex matching — treat as prefix for now
                if (std.mem.startsWith(u8, path, loc.match)) {
                    if (loc.match.len > best_len) {
                        best = loc;
                        best_len = loc.match.len;
                    }
                }
            },
        }
    }
    return best;
}

/// Find the best matching server block for a given Host header value.
/// Returns the first server if no server_name matches (default server).
pub fn matchServer(servers: []const ServerConfig, host: []const u8) *const ServerConfig {
    // Strip port from host if present
    const bare_host = if (std.mem.lastIndexOfScalar(u8, host, ':')) |i| host[0..i] else host;

    for (servers) |*s| {
        for (s.server_name) |name| {
            if (std.ascii.eqlIgnoreCase(name, bare_host)) return s;
            // Wildcard: *.example.com
            if (std.mem.startsWith(u8, name, "*.")) {
                const suffix = name[1..]; // ".example.com"
                if (std.mem.endsWith(u8, bare_host, suffix)) return s;
            }
        }
    }
    return &servers[0];
}

/// Look up an upstream pool by name within a server block.
pub fn findPool(server: *const ServerConfig, name: []const u8) ?*const UpstreamPoolConfig {
    for (server.upstream_pools) |*p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }
    return null;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "default config" {
    const cfg = default_config;
    try std.testing.expect(cfg.servers.len > 0);
    try std.testing.expect(cfg.servers[0].upstream_pools.len > 0);
    try std.testing.expect(cfg.servers[0].upstream_pools[0].upstreams.len > 0);
}

test "matchServer exact and wildcard" {
    const servers = [_]ServerConfig{
        ServerConfig{
            .server_name = @constCast(&[_][]const u8{"api.example.com"}),
            .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
        },
        ServerConfig{
            .server_name = @constCast(&[_][]const u8{"*.example.com"}),
            .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
        },
    };
    try std.testing.expectEqual(&servers[0], matchServer(&servers, "api.example.com"));
    try std.testing.expectEqual(&servers[1], matchServer(&servers, "www.example.com"));
    // fallback to first server
    try std.testing.expectEqual(&servers[0], matchServer(&servers, "other.com"));
}

test "matchLocation prefix longest wins" {
    const locs = [_]LocationConfig{
        LocationConfig{ .match = "/", .upstream_pool = "default" },
        LocationConfig{ .match = "/api/", .upstream_pool = "api" },
        LocationConfig{ .match = "/api/v2", .upstream_pool = "apiv2", .match_type = .exact },
    };
    const server = ServerConfig{
        .locations = @constCast(&locs),
        .upstream_pools = @constCast(&[_]UpstreamPoolConfig{default_upstream_pool}),
    };
    try std.testing.expectEqualStrings("default", matchLocation(&server, "/health").?.upstream_pool);
    try std.testing.expectEqualStrings("api", matchLocation(&server, "/api/users").?.upstream_pool);
    try std.testing.expectEqualStrings("apiv2", matchLocation(&server, "/api/v2").?.upstream_pool);
}
