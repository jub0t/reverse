# zproxy — Project Development Prompt

Use this prompt at the start of any new development session to restore full context.

---

## Project Overview

We are building **zproxy** — a high-performance reverse proxy for Linux written in **Zig 0.14.0**, designed to outperform Nginx on throughput, latency, and memory efficiency. It is built around Linux's `io_uring` API and uses modern kernel features unavailable to Nginx.

The project lives at:
- **Windows path**: `D:\github_repositories\reverse\v0`
- **WSL2 path**: `/mnt/d/github_repositories/reverse/v0`

---

## Developer Environment

- **Host OS**: Windows 10
- **Development environment**: WSL2 running Ubuntu 24.04.3 LTS
- **WSL2 Kernel**: 6.6.87.2-microsoft-standard-WSL2 ✅ (supports all required io_uring features)
- **Terminal**: Ubuntu terminal app (this IS WSL2 — same thing)
- **Always build and run from WSL2 terminal**, never from PowerShell
- **Zig version**: 0.14.0 (Linux x86_64 binary inside WSL2)
- **Testing on native Linux**: Ubuntu laptop (used for features that WSL2 can't support)

---

## Performance Goals

| Metric                  | Nginx (tuned)    | zproxy target   |
| ----------------------- | ---------------- | --------------- |
| Accept throughput       | ~200K conn/s     | ~800K–1M conn/s |
| p99 latency             | ~2–5ms           | ~200–500µs      |
| Memory per connection   | ~25KB            | ~4–8KB          |
| TLS overhead            | High (user copy) | Low (kTLS)      |
| Pass-through throughput | ~40Gbps          | ~100Gbps+       |

---

## Architecture

```
SO_REUSEPORT + CBPF Steering
        │
        ├── Worker 0 (core 0)    ├── Worker N (core N)
        │   io_uring ring        │   io_uring ring
        │   - multishot accept   │   - multishot accept
        │   - multishot recv     │   - multishot recv
        │   - provided buf ring  │   - provided buf ring
        │   - SEND_ZC (native)   │   - SEND_ZC (native)
        │   - registered FDs     │   - registered FDs
        │   Local upstream pool  │   Local upstream pool
        │
        ├── SIMD HTTP/1.1 + HTTP/2 Parser
        │   - AVX2 header validation
        │   - zero-allocation, zero-copy
        │   - comptime method dispatch
        │
        ├── Routing Decision
        │   ├── Inspect path  →  Upstream Pool (TFO + work-steal)
        │   └── Pass-through  →  eBPF SOCKMAP (kernel splice, native only)
        │
        └── kTLS (native only)
            sendfile/splice work on plaintext
```

---

## Project File Structure

```
reverse/v0/
├── build.zig               # Build system + feature flags
├── build.zig.zon           # Package manifest
├── README.md               # Setup and architecture docs
└── src/
    ├── main.zig            # Entry point, socket setup, worker spawning, signals
    ├── worker.zig          # Per-CPU worker thread + io_uring CQE dispatch loop
    ├── config.zig          # Config types + ZON file loader
    ├── io/
    │   └── ring.zig        # io_uring abstraction (multishot, provided bufs, SEND_ZC)
    ├── http/
    │   └── parser.zig      # SIMD HTTP/1.1 parser (zero-alloc, zero-copy)
    └── upstream/
        └── pool.zig        # Connection pool + round-robin/least-conn load balancer
```

---

## Build System — Feature Flags

```bash
# WSL2 development (disables: SOCKMAP, kTLS, NUMA, SEND_ZC)
zig build -Dwsl2=true

# Native Linux — full feature set
zig build -Doptimize=ReleaseFast

# SQPOLL mode (dedicates a kernel thread, needs root/CAP_SYS_NICE)
sudo zig build -Dsqpoll=true -Doptimize=ReleaseFast

# Run tests
zig build test -Dwsl2=true
```

Feature flags defined in `build.zig`:

| Flag      | WSL2 default | Native default | Effect                             |
| --------- | ------------ | -------------- | ---------------------------------- |
| `wsl2`    | true         | false          | Master toggle for WSL2 limitations |
| `sockmap` | false        | true           | eBPF SOCKMAP kernel splice         |
| `ktls`    | false        | true           | Kernel TLS offload                 |
| `numa`    | false        | true           | NUMA-aware memory allocation       |
| `send_zc` | false        | true           | Zero-copy send (SEND_ZC)           |
| `sqpoll`  | false        | false          | Kernel-side SQ polling             |
| `tls`     | false        | false          | TLS support via BoringSSL          |

---

## Key Technical Decisions

### io_uring Strategy
- **Multishot accept**: Submit once on listen_fd, kernel fires CQE per new connection forever
- **Multishot recv + provided buffer rings**: Kernel selects buffer at receive time — no per-socket pre-allocation. Buffer pool registered via `IORING_REGISTER_PBUF_RING`
- **SEND_ZC** (`IORING_OP_SEND_ZC`): Zero-copy send for response bodies > 16KB (native only)
- **Registered FDs**: Pre-register upstream socket FDs to eliminate atomic ref-count on every SQE
- **SQPOLL** (optional): Dedicated kernel thread polls SQ — eliminates `io_uring_enter` syscall entirely

### Threading Model
- One worker thread per logical CPU (`std.Thread.getCpuCount()`)
- Each worker owns its own io_uring ring — no cross-thread ring sharing
- Workers share only the read-only `Config` and atomic counters in `Upstream`
- CPU pinning via `sched_setaffinity` (native Linux only)
- `SO_REUSEPORT` — kernel load-balances incoming connections across all workers

### HTTP Parser (`src/http/parser.zig`)
- Uses Zig `@Vector(16, u8)` for SIMD 16-byte-at-a-time scanning
- Zero allocations — all output is slices into the input buffer
- Zero copies — no memcpy of header names/values
- Comptime method dispatch (GET/POST/PUT etc → jump table)
- Returns `error.NeedMoreData` for partial buffers (safe for streaming)

### Upstream Connection Pool (`src/upstream/pool.zig`)
- Per-worker `LocalPool` — fixed-size ring of idle fds, no mutex needed
- `LoadBalancer` supports `round_robin` and `least_connections`
- Atomic health tracking per upstream (`Upstream.healthy`)
- TCP Fast Open to upstreams (native Linux — saves one RTT on cold connections)
- TCP_NODELAY always set on upstream connections

### WSL2 vs Native Linux
Features are compile-time disabled on WSL2 via `build_options`:
- **eBPF SOCKMAP**: Not supported in WSL2 at all
- **kTLS**: Unreliable on WSL2
- **NUMA allocation**: Irrelevant (WSL2 is a single VM)
- **SEND_ZC**: Hyper-V vNIC limitation
- **CPU pinning**: Skipped on WSL2

---

## What Is Already Implemented

- [x] `io/ring.zig` — full io_uring abstraction with multishot accept, multishot recv, provided buffer rings, SEND_ZC, CQE dispatcher
- [x] `http/parser.zig` — SIMD HTTP/1.1 parser with full test suite
- [x] `upstream/pool.zig` — per-worker keepalive pool, round-robin + least-connections LB, atomic health
- [x] `worker.zig` — per-CPU event loop owning ring + pool, full connection state machine
- [x] `main.zig` — `SO_REUSEPORT` listen socket, worker spawning, CPU pinning, SIGINT/SIGTERM handler
- [x] `config.zig` — config types and ZON loader stub
- [x] `build.zig` — feature flag system for WSL2 vs native Linux

---

## What Needs To Be Built Next (in priority order)

1. **Fix compilation errors** — wire up remaining Zig 0.14.0 API differences (IoUring method names, sigaction API, fcntl constants)
2. **Upstream recv path** — when upstream sends a response, forward it back to the client
3. **Header rewriting** — add `X-Forwarded-For`, rewrite `Host`, strip hop-by-hop headers
4. **ZON config parser** — replace the stub in `config.zig` with actual `std.zon.parseFromSlice`
5. **Health checker** — periodic TCP connect to each upstream, update `Upstream.healthy`
6. **HTTP/2 support** — HPACK header compression + frame parsing
7. **kTLS** — after BoringSSL handshake, push session keys to kernel via `setsockopt(TCP_ULP, "tls")`
8. **eBPF SOCKMAP** — load BPF program for kernel-level socket splicing (WebSocket, CONNECT tunnels)
9. **Metrics endpoint** — `/metrics` returning per-worker stats in Prometheus format
10. **NUMA-aware allocation** — `mbind()` for buffer pools on multi-socket servers

---

## Config File Format (`zproxy.zon`)

```zig
.{
    .bind = "0.0.0.0",
    .port = 8080,
    .workers = 0,                    // 0 = auto (one per logical CPU)
    .backlog = 4096,
    .io_uring_sq_depth = 4096,
    .io_uring_buf_count = 1024,
    .io_uring_buf_size = 32768,      // 32KB per buffer
    .upstream = .{
        .addrs = .{ "127.0.0.1:3000", "127.0.0.1:3001" },
        .strategy = .round_robin,    // or .least_connections
        .pool_size = 64,             // idle connections per upstream per worker
        .connect_timeout_ms = 2000,
        .keepalive = true,
        .tcp_fast_open = true,
        .health_check_interval_ms = 5000,
    },
    .log_level = .info,
}
```

---

## CQE Dispatch Flow

```
io_uring CQE arrives
        │
        ├── tag = .accept   → onAccept()  → store Conn, submitMultishotRecv()
        ├── tag = .recv     → onRecv()    → parse HTTP or forward upstream data
        ├── tag = .send     → onSend()    → keepalive reset or close
        ├── tag = .connect  → onConnect() → forwardRequest() or send 502
        └── tag = .close    → onClose()   → return upstream conn to pool
```

User-data encoding in SQEs (u64):
- Top 8 bits = Tag enum (accept/recv/send/connect/close)
- Bottom 56 bits = file descriptor (i32 bitcast to u32, zero-extended)

---

## References

- Zig 0.14.0 release notes: https://ziglang.org/download/0.14.0/release-notes.html
- io_uring docs: https://kernel.dk/io_uring.pdf
- io_uring multishot + provided buffers: https://lwn.net/Articles/879758/
- eBPF SOCKMAP: https://lwn.net/Articles/731133/
- kTLS: https://www.kernel.org/doc/html/latest/networking/tls.html
- Nginx source (for reference): https://github.com/nginx/nginx
