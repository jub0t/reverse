const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Feature flags ──────────────────────────────────────────────────────────
    // Pass `-Dwsl2=true` when building on WSL2 to disable unsupported features.
    // On native Linux leave unset (defaults to false = full feature set).
    //
    //   WSL2:         zig build -Dwsl2=true
    //   Native Linux: zig build
    // ──────────────────────────────────────────────────────────────────────────
    const wsl2 = b.option(bool, "wsl2", "Build for WSL2 (disables SOCKMAP, kTLS, NUMA, SEND_ZC)") orelse false;
    const sqpoll = b.option(bool, "sqpoll", "Enable io_uring SQPOLL mode (dedicates a kernel thread, needs CAP_SYS_NICE)") orelse false;
    const tls = b.option(bool, "tls", "Enable TLS via BoringSSL") orelse false;

    // Expose feature flags as comptime constants inside the binary
    const options = b.addOptions();
    options.addOption(bool, "wsl2", wsl2);
    options.addOption(bool, "sqpoll", sqpoll);
    options.addOption(bool, "tls", tls);
    options.addOption(bool, "sockmap", !wsl2); // eBPF SOCKMAP — native only
    options.addOption(bool, "ktls", !wsl2); // kTLS        — native only
    options.addOption(bool, "numa", !wsl2); // NUMA alloc  — native only
    options.addOption(bool, "send_zc", !wsl2); // SEND_ZC     — native only

    const exe = b.addExecutable(.{
        .name = "zproxy",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addOptions("build_options", options);

    // Link libc for BoringSSL FFI (always — even without TLS we may need it later)
    exe.linkLibC();

    b.installArtifact(exe);

    // ── Run step ──────────────────────────────────────────────────────────────
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zproxy");
    run_step.dependOn(&run_cmd.step);

    // ── Test step ─────────────────────────────────────────────────────────────
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addOptions("build_options", options);
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
