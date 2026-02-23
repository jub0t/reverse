/// bench/main.zig — zproxy micro-benchmarks
///
/// Run: zig build bench -- --duration=10
const std = @import("std");
const build_options = @import("build_options");

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var duration: u64 = 5;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--duration=")) {
            duration = try std.fmt.parseInt(u64, arg["--duration=".len..], 10);
        }
    }

    std.debug.print("zproxy bench — duration={}s\n", .{duration});
    std.debug.print("  tls={} h2_upstream={} sendfile={}\n", .{
        build_options.tls,
        build_options.h2_upstream,
        build_options.sendfile,
    });

    try benchHttpParse(duration);
}

fn benchHttpParse(duration_s: u64) !void {
    const parser = @import("../http/parser.zig");

    const sample =
        "GET /api/v1/users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Accept: application/json\r\n" ++
        "\r\n";

    var req: parser.Request = undefined;
    var iters: u64 = 0;
    const deadline = std.time.nanoTimestamp() + @as(i128, duration_s) * std.time.ns_per_s;

    while (std.time.nanoTimestamp() < deadline) {
        _ = parser.parse(sample, &req) catch {};
        iters += 1;
    }

    const ns_per_iter = @as(f64, @floatFromInt(duration_s * std.time.ns_per_s)) / @as(f64, @floatFromInt(iters));
    std.debug.print("  http/parse: {d:.1} ns/iter  ({d} iter/s)\n", .{
        ns_per_iter,
        @as(u64, @intFromFloat(1e9 / ns_per_iter)),
    });
}
