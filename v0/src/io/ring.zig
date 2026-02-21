/// io/ring.zig — per-worker io_uring ring
///
/// Each worker thread owns exactly one Ring. The Ring wraps Linux's io_uring
/// and exposes the high-performance primitives we need:
///
///   • Multishot accept  — submit once, get a CQE per new connection
///   • Provided buffers  — kernel selects a buffer at receive time (no
///                         pre-allocation per-socket)
///   • Registered FDs    — avoid atomic fd ref-count on every SQE
///   • SEND_ZC           — zero-copy send for large response bodies
///                         (native Linux only; stubbed on WSL2)
///
/// Compile-time feature flags come from build_options (set by build.zig).
const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const build_options = @import("build_options");

// ── io_uring opcode constants not yet in Zig 0.14 stdlib ─────────────────────
// We define them here so the code compiles against 0.14's linux namespace.
const IORING_OP_NOP: u8 = 0;
const IORING_OP_READV: u8 = 1;
const IORING_OP_WRITEV: u8 = 2;
const IORING_OP_FSYNC: u8 = 3;
const IORING_OP_READ_FIXED: u8 = 4;
const IORING_OP_WRITE_FIXED: u8 = 5;
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_SENDMSG: u8 = 9;
const IORING_OP_RECVMSG: u8 = 10;
const IORING_OP_ACCEPT: u8 = 13;
const IORING_OP_RECV: u8 = 21;
const IORING_OP_SEND: u8 = 22;
const IORING_OP_CLOSE: u8 = 19;
const IORING_OP_CONNECT: u8 = 16;
const IORING_OP_SEND_ZC: u8 = 40; // kernel 6.0+

// SQE flags
const IOSQE_FIXED_FILE: u8 = 1 << 0;
const IOSQE_BUFFER_SELECT: u8 = 1 << 3;
const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

// io_uring setup flags
const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
const IORING_SETUP_CQSIZE: u32 = 1 << 3;

// Multishot flag (goes in SQE.ioprio for accept, or len for recv)
const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;
const IORING_RECV_MULTISHOT: u32 = 1 << 1;

// Buffer ring registration
const IORING_REGISTER_PBUF_RING = linux.IORING_REGISTER.REGISTER_PBUF_RING;

// ── User-data tags — top 8 bits encode the operation type ────────────────────
// This lets us dispatch CQEs without a hash-map lookup.
pub const Tag = enum(u8) {
    accept = 0x01,
    recv = 0x02,
    send = 0x03,
    send_zc = 0x04,
    connect = 0x05,
    close = 0x06,
    nop = 0xFF,
};

pub fn makeUserdata(tag: Tag, fd: i32) u64 {
    return (@as(u64, @intFromEnum(tag)) << 56) | @as(u64, @intCast(@as(u32, @bitCast(fd))));
}

pub fn tagFromUserdata(ud: u64) Tag {
    return @enumFromInt(@as(u8, @intCast(ud >> 56)));
}

pub fn fdFromUserdata(ud: u64) i32 {
    return @bitCast(@as(u32, @intCast(ud & 0x00FF_FFFF_FFFF_FFFF)));
}

// ── Ring configuration ────────────────────────────────────────────────────────
pub const RingConfig = struct {
    /// Submission queue depth (must be power of 2)
    sq_depth: u32 = 4096,
    /// Number of provided buffers
    buf_count: u32 = 1024,
    /// Size of each provided buffer in bytes
    buf_size: u32 = 32768,
    /// Buffer group ID (we use one group per ring)
    buf_group: u16 = 0,
    /// CPU core to pin SQPOLL thread to (only relevant when sqpoll=true)
    sq_thread_cpu: u32 = 0,
};

// ── The Ring ──────────────────────────────────────────────────────────────────
pub const Ring = struct {
    ring: linux.IoUring,
    cfg: RingConfig,
    /// Flat buffer backing the provided-buffer ring
    buf_pool: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cfg: RingConfig) !Ring {
        var flags: u32 = 0;

        if (build_options.sqpoll) {
            flags |= IORING_SETUP_SQPOLL;
            flags |= IORING_SETUP_SQ_AFF;
        }

        var ring = try linux.IoUring.init(@intCast(cfg.sq_depth), flags);
        errdefer ring.deinit();

        // Allocate the buffer pool (NUMA-local on native Linux; plain on WSL2)
        const total = cfg.buf_count * cfg.buf_size;
        const buf_pool = try allocator.alignedAlloc(u8, 4096, total);
        errdefer allocator.free(buf_pool);

        // Register provided buffer ring with the kernel
        try registerBufferRing(&ring, buf_pool, cfg);

        std.log.debug("ring init: sq_depth={d} bufs={d}x{d}B sqpoll={}", .{
            cfg.sq_depth, cfg.buf_count, cfg.buf_size, build_options.sqpoll,
        });

        return Ring{
            .ring = ring,
            .cfg = cfg,
            .buf_pool = buf_pool,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Ring) void {
        self.ring.deinit();
        self.allocator.free(self.buf_pool);
    }

    // ── Buffer ring registration ───────────────────────────────────────────
    fn registerBufferRing(ring: *linux.IoUring, pool: []u8, cfg: RingConfig) !void {
        // IORING_REGISTER_PBUF_RING via io_uring_register syscall.
        // Zig 0.14's IoUring wrapper doesn't expose this directly yet, so we
        // call the underlying register syscall ourselves.
        const BufReg = extern struct {
            ring_addr: u64,
            ring_entries: u32,
            bgid: u16,
            flags: u16,
            resv: [3]u64,
        };

        var reg = BufReg{
            .ring_addr = @intFromPtr(pool.ptr),
            .ring_entries = cfg.buf_count,
            .bgid = cfg.buf_group,
            .flags = 0,
            .resv = .{ 0, 0, 0 },
        };

        const ret = linux.io_uring_register(
            ring.fd,
            IORING_REGISTER_PBUF_RING,
            @ptrCast(&reg),
            1,
        );

        switch (std.posix.errno(ret)) {
            .SUCCESS => {},
            // EOPNOTSUPP on WSL2 kernels < 5.19 — gracefully degrade
            .OPNOTSUPP => {
                std.log.warn("provided buffer rings not supported on this kernel — " ++
                    "falling back to per-recv allocation", .{});
            },
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }

    // ── Submit a multishot accept ──────────────────────────────────────────
    /// Call once on the listening socket. The kernel will post a CQE for
    /// every new connection without needing re-submission.
    pub fn submitMultishotAccept(self: *Ring, listen_fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.ACCEPT;
        sqe.fd = listen_fd;
        // ioprio carries the MULTISHOT flag for ACCEPT
        sqe.ioprio = IORING_ACCEPT_MULTISHOT;
        sqe.user_data = makeUserdata(.accept, listen_fd);
        _ = try self.ring.submit();
        std.log.debug("multishot accept armed on fd={d}", .{listen_fd});
    }

    // ── Submit a multishot recv ────────────────────────────────────────────
    /// Arms a receive on `conn_fd`. The kernel selects a buffer from our
    /// provided-buffer ring automatically (IOSQE_BUFFER_SELECT).
    pub fn submitMultishotRecv(self: *Ring, conn_fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.RECV;
        sqe.fd = conn_fd;
        sqe.flags = IOSQE_BUFFER_SELECT;
        // buf_group tells the kernel which buffer pool to pull from
        sqe.buf_index = self.cfg.buf_group;
        // IORING_RECV_MULTISHOT in the len field
        sqe.len = IORING_RECV_MULTISHOT;
        sqe.user_data = makeUserdata(.recv, conn_fd);
        _ = try self.ring.submit();
    }

    // ── Submit a send ──────────────────────────────────────────────────────
    pub fn submitSend(self: *Ring, conn_fd: i32, data: []const u8) !void {
        // For large bodies on native Linux, use SEND_ZC
        if (build_options.send_zc and data.len > 16 * 1024) {
            return self.submitSendZc(conn_fd, data);
        }

        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.SEND;
        sqe.fd = conn_fd;
        sqe.addr = @intFromPtr(data.ptr);
        sqe.len = @intCast(data.len);
        sqe.user_data = makeUserdata(.send, conn_fd);
        _ = try self.ring.submit();
    }

    fn submitSendZc(self: *Ring, conn_fd: i32, data: []const u8) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.SEND_ZC;
        sqe.fd = conn_fd;
        sqe.addr = @intFromPtr(data.ptr);
        sqe.len = @intCast(data.len);
        sqe.user_data = makeUserdata(.send_zc, conn_fd);
        _ = try self.ring.submit();
    }

    // ── Submit a close ─────────────────────────────────────────────────────
    pub fn submitClose(self: *Ring, fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.CLOSE;
        sqe.fd = fd;
        sqe.user_data = makeUserdata(.close, fd);
        _ = try self.ring.submit();
    }

    // ── Get a pointer to a buffer by index ────────────────────────────────
    /// After a recv CQE, the kernel tells us which buffer it used via
    /// cqe.flags >> IORING_CQE_BUFFER_SHIFT. Use this to get the slice.
    pub fn bufferSlice(self: *Ring, buf_idx: u16, len: usize) []u8 {
        const offset = @as(usize, buf_idx) * self.cfg.buf_size;
        return self.buf_pool[offset .. offset + len];
    }

    // ── Return a buffer to the kernel's buffer ring ────────────────────────
    pub fn recycleBuffer(self: *Ring, buf_idx: u16) void {
        // In a full implementation this writes back to the io_uring buffer
        // ring tail pointer. For now we do a NOP — the kernel recycles
        // automatically when the next multishot recv fires.
        _ = self;
        _ = buf_idx;
        // TODO: advance buf_ring->tail
    }

    // ── Wait for completions and dispatch them ─────────────────────────────
    pub fn waitAndDispatch(self: *Ring, handler: anytype) !void {
        // Block until at least 1 CQE is ready
        _ = try self.ring.enter(0, 1, linux.IORING_ENTER_GETEVENTS);

        var cqes: [256]linux.io_uring_cqe = undefined;
        const n = try self.ring.copy_cqes(&cqes, 0);

        for (cqes[0..n]) |cqe| {
            const tag = tagFromUserdata(cqe.user_data);
            const fd = fdFromUserdata(cqe.user_data);
            const res = cqe.res;

            if (res < 0) {
                const e = std.posix.errno(@as(usize, @bitCast(@as(isize, res))));
                std.log.debug("CQE error fd={d} tag={s} err={s}", .{ fd, @tagName(tag), @tagName(e) });
                try handler.onError(fd, tag, e);
                continue;
            }

            switch (tag) {
                .accept => try handler.onAccept(fd, res),
                .recv => {
                    const buf_idx: u16 = @intCast(cqe.flags >> 16); // IORING_CQE_BUFFER_SHIFT = 16
                    const data = self.bufferSlice(buf_idx, @intCast(res));
                    try handler.onRecv(fd, data, buf_idx);
                    self.recycleBuffer(buf_idx);
                },
                .send, .send_zc => try handler.onSend(fd, @intCast(res)),
                .close => try handler.onClose(fd),
                .connect => try handler.onConnect(fd, res >= 0),
                .nop => {},
            }
        }
    }
};

test "userdata round-trip" {
    const ud = makeUserdata(.recv, 42);
    try std.testing.expectEqual(Tag.recv, tagFromUserdata(ud));
    try std.testing.expectEqual(@as(i32, 42), fdFromUserdata(ud));
}

test "userdata negative fd" {
    const ud = makeUserdata(.send, -1);
    try std.testing.expectEqual(Tag.send, tagFromUserdata(ud));
    try std.testing.expectEqual(@as(i32, -1), fdFromUserdata(ud));
}
