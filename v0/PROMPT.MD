# zproxy — Project Development Prompt (v2)

Paste this at the start of any new development session to restore full context.

---

## Project Overview

**zproxy** is a high-performance reverse proxy written in **Zig 0.14.0**, targeting Linux. It is built around `io_uring` for maximum throughput and minimum latency, designed to outperform Nginx on throughput, p99 latency, and memory efficiency.

---

## Environments

| Environment | Details |
|---|---|
| Dev machine | Windows 10, Ubuntu 24.04.3 LTS via WSL2 |
| WSL2 kernel | 6.6.87.2-microsoft-standard-WSL2 |
| Test machine | Ubuntu laptop (native Linux, full feature set) |
| Zig version | 0.14.0 (Linux x86_64 binary at `~/zig-linux-x86_64-0.14.0/`) |
| Project path (WSL2) | `/mnt/d/github_repositories/reverse/v0` |
| Project path (laptop) | `~/Github/reverse/v0` |
| Zig installed (laptop) | `/usr/local/zig-0.14.0/` |

**Always build and run from the Ubuntu/WSL2 terminal, never PowerShell.**

---

## Build Commands

```bash
# WSL2 development
zig build -Dwsl2=true

# WSL2 tests
zig build test -Dwsl2=true

# Native Linux — full feature set
zig build -Doptimize=ReleaseFast

# Run
./zig-out/bin/zproxy

# Run with config file
./zig-out/bin/zproxy zproxy.zon
```

---

## Feature Flags (build.zig)

| Flag | WSL2 | Native | Description |
|---|---|---|---|
| `-Dwsl2=true` | true | false | Master WSL2 toggle |
| `sockmap` | false | true | eBPF SOCKMAP (auto-set from wsl2) |
| `ktls` | false | true | Kernel TLS (auto-set from wsl2) |
| `numa` | false | true | NUMA-aware alloc (auto-set from wsl2) |
| `send_zc` | false | true | Zero-copy send (auto-set from wsl2) |
| `-Dsqpoll=true` | false | false | Kernel SQ polling (needs root) |
| `-Dtls=true` | false | false | TLS via BoringSSL (WIP) |

---

## Project File Structure

```
reverse/v0/
├── build.zig               # Build system + feature flags
├── build.zig.zon           # Package manifest
├── zproxy.zon              # Runtime config file (optional)
└── src/
    ├── main.zig            # Entry point, socket, workers, signals
    ├── worker.zig          # Per-CPU worker + CQE dispatch loop
    ├── config.zig          # Config types + ZON loader stub
    ├── io/
    │   └── ring.zig        # io_uring abstraction
    ├── http/
    │   └── parser.zig      # SIMD HTTP/1.1 parser
    └── upstream/
        └── pool.zig        # Connection pool + load balancer
```

---

## build.zig.zon (correct format for Zig 0.14.0)

```zig
.{
    .name = .zproxy,
    .fingerprint = 0xae2bb1a7aa8888cb,
    .version = "0.0.0",
    .dependencies = .{},
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
```

---

## Architecture

```
SO_REUSEPORT listen socket (shared across all workers)
        │
        ├── Worker 0 (core 0)   ├── Worker N (core N)
        │   io_uring ring       │   io_uring ring
        │   - multishot accept  │   - multishot accept
        │   - per-conn recv     │   - per-conn recv
        │   - send / send_zc    │   - send / send_zc
        │   - 100ms timeout     │   - 100ms timeout
        │   Local upstream pool │   Local upstream pool
        │
        ├── SIMD HTTP/1.1 Parser (zero-alloc, zero-copy)
        │
        ├── Round-robin / Least-connections Load Balancer
        │
        └── Upstream TCP connections (keepalive pool per worker)
```

---

## Key Design Decisions Made During Development

### io_uring recv strategy
**Provided buffer rings were removed.** The original design used `IORING_REGISTER_PBUF_RING` (kernel selects buffer at recv time). This failed in practice — when the buffer ring isn't set up correctly, recv CQEs complete with `res=0` (no buffer available), which was being misread as EOF and closing connections immediately.

**Current approach**: Each `Conn` struct owns an 8KB `req_buf[8192]u8`. On accept, we get a stable pointer to that buffer and pass it directly to `submitRecv`. This is simpler, works on both WSL2 and native Linux, and has no hidden failure modes.

Provided buffer rings can be re-added later as an optimization once the core proxy logic is working.

### Shutdown mechanism
Workers block in `io_uring_enter` (a blocking syscall). To shut them down cleanly:
- A global `shutdown_flag: std.atomic.Value(bool)` is shared across all workers
- Each worker submits a recurring `TIMEOUT` SQE (100ms interval) so the event loop wakes up periodically
- On `onTimeout()`, the worker checks `shutdown_flag` and resubmits the timeout if not shutting down
- On Ctrl+C, `main()` sets `shutdown_flag = true` and closes the listen socket
- Workers exit their `while (!shutdown_flag.load(...))` loop within 100ms

**tkill approach was abandoned** — `t.impl.handle` on WSL2/pthreads returns a `*pthread_t` opaque pointer, not a Linux TID. Getting the real TID requires the worker to publish it via an atomic at startup, which added complexity. The timeout polling approach is simpler and reliable.

### CQE dispatch
User-data encoding in SQEs:
- Top 8 bits = `Tag` enum (accept/recv/send/connect/close/timeout/nop)
- Bottom 56 bits = file descriptor (i32 bitcast to u32, zero-extended)

`waitAndDispatch` handles:
- `res <= 0`: if `res < 0` → error path, if `res == 0` → EOF → call `onClose`
- `tag == .timeout` → call `onTimeout` (checked before error path since -ETIME is normal)
- All other tags dispatched normally

### Zig 0.14.0 API differences from original code
Several APIs moved or changed in 0.14.0:
- `std.os.*` → `std.posix.*` (socket, bind, listen, close, setsockopt, etc.)
- `os.fd_t` → `std.posix.fd_t`
- `linux.getErrno()` → `std.posix.errno()`
- `os.unexpectedErrno()` → `std.posix.unexpectedErrno()`
- `linux.IoUring.init(entries, flags)` — entries is `u16`, not `u32` (use `@intCast`)
- `linux.IORING_REGISTER` is an enum — use `.REGISTER_PBUF_RING` not a raw `u32`
- `linux.IORING_OP` is an enum — use `.ACCEPT`, `.RECV`, `.SEND`, `.CLOSE`, etc.
- `linux.O.NONBLOCK` is a packed struct field — use `std.posix.O{ .NONBLOCK = true }`
- `std.posix.sigaction()` does not return an error union — no `catch {}` needed
- `io_uring.enter()` returns an error union — use `_ = try self.ring.enter(...)`
- `build.zig.zon` requires `.name = .zproxy` (enum literal) and `.fingerprint` field

---

## Current Status

### Working
- [x] Compiles clean on both WSL2 (`-Dwsl2=true`) and native Linux (`-Doptimize=ReleaseFast`)
- [x] All tests pass (`zig build test -Dwsl2=true`)
- [x] 4 workers start, each with its own io_uring ring
- [x] Multishot accept armed on listen socket
- [x] Ctrl+C exits cleanly (shutdown_flag + timeout polling)
- [x] Accepts TCP connections from curl
- [x] Per-connection recv buffer wired up correctly

### In Progress / Known Issues
- [ ] `Connection reset by peer` — proxy accepts connection but response path is incomplete
- [ ] Upstream connect SQE not yet submitted via io_uring (uses blocking `connectNew`)
- [ ] Response from upstream not forwarded back to client yet
- [ ] `onConnect` CQE handler not wired to the ring (TODO comment in worker.zig)

### Next Steps (in priority order)
1. **Fix upstream connect** — submit `IORING_OP_CONNECT` SQE via ring instead of blocking connect
2. **Wire upstream recv** — after connect, arm recv on upstream_fd to get response
3. **Forward response** — when upstream recv fires, send data back to client_fd
4. **Test end-to-end** — `curl http://localhost:8080/` should return Python HTTP server response
5. **Header rewriting** — add `X-Forwarded-For`, rewrite `Host`, strip hop-by-hop headers
6. **ZON config parser** — replace stub in `config.zig` with real `std.zon.parseFromSlice`
7. **Health checker** — periodic TCP ping to each upstream, update `Upstream.healthy`
8. **HTTP/2** — HPACK + frame parsing
9. **kTLS** — push session keys to kernel after BoringSSL handshake
10. **eBPF SOCKMAP** — kernel splice for WebSocket/CONNECT pass-through

---

## Config File Format (`zproxy.zon`)

The ZON parser is currently stubbed — it loads the file but uses hardcoded defaults. The config types in `config.zig` define the intended format:

```zig
.{
    .bind = "0.0.0.0",
    .port = 8080,
    .workers = 0,                    // 0 = auto (one per logical CPU)
    .backlog = 4096,
    .io_uring_sq_depth = 4096,
    .io_uring_buf_count = 1024,
    .io_uring_buf_size = 32768,
    .upstream = .{
        .addrs = .{ "127.0.0.1:3000", "127.0.0.1:3001" },
        .strategy = .round_robin,    // or .least_connections
        .pool_size = 64,
        .connect_timeout_ms = 2000,
        .keepalive = true,
        .tcp_fast_open = true,
        .health_check_interval_ms = 5000,
    },
    .log_level = .info,
}
```

Default upstream (used when no config file found): `127.0.0.1:3000`

---

## Testing

```bash
# Terminal 1 — fake backend
python3 -m http.server 3000

# Terminal 2 — proxy
./zig-out/bin/zproxy

# Terminal 3 — test
curl -v http://localhost:8080/
curl -v http://localhost:8080/ http://localhost:8080/ http://localhost:8080/
```

---

## Performance Goals

| Metric | Nginx (tuned) | zproxy target |
|---|---|---|
| Accept throughput | ~200K conn/s | ~800K–1M conn/s |
| p99 latency | ~2–5ms | ~200–500µs |
| Memory per connection | ~25KB | ~4–8KB |
| TLS overhead | High (user copy) | Low (kTLS) |
| Pass-through throughput | ~40Gbps | ~100Gbps+ (SOCKMAP) |

---

## References

- Zig 0.14.0 release notes: https://ziglang.org/download/0.14.0/release-notes.html
- io_uring docs: https://kernel.dk/io_uring.pdf
- io_uring multishot: https://lwn.net/Articles/879758/
- eBPF SOCKMAP: https://lwn.net/Articles/731133/
- kTLS: https://www.kernel.org/doc/html/latest/networking/tls.html