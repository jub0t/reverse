/// build.zig — zproxy build script
///
/// New feature flags added in this revision:
///   -Dtls=true          enable TLS termination (requires OpenSSL 3.x)
///   -Dh2_upstream=true  enable HTTP/2 upstream support
///   -Dsendfile=true     use IORING_OP_SENDFILE for static files (kernel 5.6+)
///
/// Existing flags unchanged:
///   -Dsqpoll    -Dsend_zc    -Dwsl2    -Dsockmap    -Dktls
///
/// Example invocations:
///   zig build                          # minimal, no TLS, H1 only
///   zig build -Dtls -Dh2_upstream      # full feature set
///   zig build -Dwsl2 -Dsqpoll=false    # WSL2 dev machine
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Feature flags ──────────────────────────────────────────────────────

    const wsl2 = b.option(bool, "wsl2", "Target WSL2 (disables SQPOLL, reduces ring depth)") orelse false;
    const sqpoll = b.option(bool, "sqpoll", "Use IORING_SETUP_SQPOLL (requires CAP_SYS_NICE)") orelse !wsl2;
    const sockmap = b.option(bool, "sockmap", "Use eBPF sockmap for zero-copy proxy path") orelse false;
    const send_zc = b.option(bool, "send_zc", "Use IORING_OP_SEND_ZC for large sends (kernel 6.0+)") orelse false;
    const ktls = b.option(bool, "ktls", "Enable kTLS kernel offload after TLS handshake") orelse false;

    // ── New feature flags ──────────────────────────────────────────────────
    const tls = b.option(bool, "tls", "Enable TLS termination via OpenSSL 3.x") orelse false;
    const h2_upstream = b.option(bool, "h2_upstream", "Enable HTTP/2 upstream connections") orelse false;
    const sendfile = b.option(bool, "sendfile", "Use IORING_OP_SENDFILE for static file serving") orelse true;

    // ── Build options module ───────────────────────────────────────────────

    const options = b.addOptions();
    options.addOption(bool, "wsl2", wsl2);
    options.addOption(bool, "sqpoll", sqpoll);
    options.addOption(bool, "sockmap", sockmap);
    options.addOption(bool, "send_zc", send_zc);
    options.addOption(bool, "ktls", ktls);
    options.addOption(bool, "tls", tls);
    options.addOption(bool, "h2_upstream", h2_upstream);
    options.addOption(bool, "sendfile", sendfile);

    // ── Executable ────────────────────────────────────────────────────────

    const exe = b.addExecutable(.{
        .name = "zproxy",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addOptions("build_options", options);

    // ── Source modules ─────────────────────────────────────────────────────
    // All modules compile unconditionally; runtime feature flags gate
    // actual use. This keeps the dependency graph simple and avoids
    // conditional compilation pitfalls in Zig's lazy analysis.

    const ring_mod = b.addModule("io_ring", .{ .root_source_file = b.path("src/io/ring.zig") });
    const parser_mod = b.addModule("http_parser", .{ .root_source_file = b.path("src/http/parser.zig") });
    const pool_mod = b.addModule("upstream_pool", .{ .root_source_file = b.path("src/upstream/pool.zig") });
    const config_mod = b.addModule("config", .{ .root_source_file = b.path("src/config.zig") });
    const h2_mod = b.addModule("upstream_h2", .{ .root_source_file = b.path("src/upstream/h2.zig") });
    const tls_mod = b.addModule("tls_context", .{ .root_source_file = b.path("src/tls/context.zig") });
    const static_mod = b.addModule("static_serve", .{ .root_source_file = b.path("src/static/serve.zig") });

    _ = ring_mod;
    _ = parser_mod;
    _ = pool_mod;
    _ = config_mod;
    _ = h2_mod;
    _ = tls_mod;
    _ = static_mod;

    // ── OpenSSL linkage (only when TLS is enabled) ─────────────────────────
    // We gate the C linkage on the tls flag to keep a zero-C-dep default
    // build path. This matters for reproducible builds and Alpine musl targets.

    if (tls) {
        exe.linkLibC();
        exe.linkSystemLibrary("ssl"); // libssl.so / libssl.a
        exe.linkSystemLibrary("crypto"); // libcrypto.so / libcrypto.a

        // Optional: static link against a vendored OpenSSL build.
        // Uncomment and adjust path if you want a hermetic binary:
        //   exe.addLibraryPath(b.path("third_party/openssl/lib"));
        //   exe.addIncludePath(b.path("third_party/openssl/include"));
    }

    b.installArtifact(exe);

    // ── Run step ──────────────────────────────────────────────────────────

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zproxy");
    run_step.dependOn(&run_cmd.step);

    // ── Tests ─────────────────────────────────────────────────────────────
    // Each module has its own test block. Run all with: zig build test

    const test_filter = b.option([]const u8, "test-filter", "Filter test names");

    const test_files = [_][]const u8{
        "src/io/ring.zig",
        "src/http/parser.zig",
        "src/upstream/h2.zig",
        "src/static/serve.zig",
        "src/config.zig",
        "src/toml.zig",
    };

    const test_step = b.step("test", "Run all unit tests");

    for (test_files) |file| {
        const unit_test = b.addTest(.{
            .root_source_file = b.path(file),
            .target = target,
            .optimize = optimize,
            .filter = test_filter,
        });
        unit_test.root_module.addOptions("build_options", options);
        if (tls) {
            unit_test.linkLibC();
            unit_test.linkSystemLibrary("ssl");
            unit_test.linkSystemLibrary("crypto");
        }
        const run_test = b.addRunArtifact(unit_test);
        test_step.dependOn(&run_test.step);
    }

    // ── Benchmarks ────────────────────────────────────────────────────────
    // zig build bench -- --duration=30

    const bench = b.addExecutable(.{
        .name = "zproxy-bench",
        .root_source_file = b.path("src/bench/main.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench.root_module.addOptions("build_options", options);
    const bench_step = b.step("bench", "Run micro-benchmarks");
    bench_step.dependOn(&b.addRunArtifact(bench).step);

    // ── Emit compilation summary ───────────────────────────────────────────

    std.debug.print(
        \\
        \\  zproxy build configuration:
        \\    tls={} h2_upstream={} sendfile={}
        \\    sqpoll={} send_zc={} ktls={} sockmap={} wsl2={}
        \\
    , .{ tls, h2_upstream, sendfile, sqpoll, send_zc, ktls, sockmap, wsl2 });
}
