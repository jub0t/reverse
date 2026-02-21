/// io/ring.zig — per-worker io_uring ring
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

// SQE flags
const IOSQE_BUFFER_SELECT: u8 = 1 << 3;

// io_uring setup flags
const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_SETUP_SQ_AFF: u32 = 1 << 2;

// Multishot flags
const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;
const IORING_RECV_MULTISHOT: u32 = 1 << 1;

// Buffer ring registration
const IORING_REGISTER_PBUF_RING = linux.IORING_REGISTER.REGISTER_PBUF_RING;

// ── User-data tags ────────────────────────────────────────────────────────────
pub const Tag = enum(u8) {
    accept = 0x01,
    recv = 0x02,
    send = 0x03,
    send_zc = 0x04,
    connect = 0x05,
    close = 0x06,
    timeout = 0x07,
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
    sq_depth: u32 = 4096,
    buf_count: u32 = 1024,
    buf_size: u32 = 32768,
    buf_group: u16 = 0,
    sq_thread_cpu: u32 = 0,
};

// ── The Ring ──────────────────────────────────────────────────────────────────
pub const Ring = struct {
    ring: linux.IoUring,
    cfg: RingConfig,
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

        const total = cfg.buf_count * cfg.buf_size;
        const buf_pool = try allocator.alignedAlloc(u8, 4096, total);
        errdefer allocator.free(buf_pool);

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
            .OPNOTSUPP => {
                std.log.warn("provided buffer rings not supported — falling back", .{});
            },
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }

    // ── Submit a multishot accept ──────────────────────────────────────────
    pub fn submitMultishotAccept(self: *Ring, listen_fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.ACCEPT;
        sqe.fd = listen_fd;
        sqe.ioprio = IORING_ACCEPT_MULTISHOT;
        sqe.user_data = makeUserdata(.accept, listen_fd);
        _ = try self.ring.submit();
        std.log.debug("multishot accept armed on fd={d}", .{listen_fd});
    }

    // ── Submit a multishot recv ────────────────────────────────────────────
    pub fn submitMultishotRecv(self: *Ring, conn_fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.RECV;
        sqe.fd = conn_fd;
        sqe.flags = IOSQE_BUFFER_SELECT;
        sqe.buf_index = self.cfg.buf_group;
        sqe.len = IORING_RECV_MULTISHOT;
        sqe.user_data = makeUserdata(.recv, conn_fd);
        _ = try self.ring.submit();
    }

    // ── Submit a send ──────────────────────────────────────────────────────
    pub fn submitSend(self: *Ring, conn_fd: i32, data: []const u8) !void {
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

    // ── Submit a timeout ───────────────────────────────────────────────────
    /// Fires a CQE after `ms` milliseconds. Used to periodically wake the
    /// worker loop so it can check the shutdown_flag.
    pub fn submitTimeout(self: *Ring, ms: u64) !void {
        const sqe = try self.ring.get_sqe();
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        sqe.opcode = linux.IORING_OP.TIMEOUT;

        // Allocate a timespec on the heap — the kernel reads it asynchronously
        const ts = try self.allocator.create(linux.kernel_timespec);
        ts.* = .{
            .sec = 0,
            .nsec = @intCast(ms * std.time.ns_per_ms),
        };

        sqe.addr = @intFromPtr(ts);
        sqe.len = 1; // number of timespec structs
        sqe.user_data = makeUserdata(.timeout, 0);
        _ = try self.ring.submit();
    }

    // ── Buffer helpers ─────────────────────────────────────────────────────
    pub fn bufferSlice(self: *Ring, buf_idx: u16, len: usize) []u8 {
        const offset = @as(usize, buf_idx) * self.cfg.buf_size;
        return self.buf_pool[offset .. offset + len];
    }

    pub fn recycleBuffer(self: *Ring, buf_idx: u16) void {
        _ = self;
        _ = buf_idx;
        // TODO: advance buf_ring->tail
    }

    // ── Wait for completions and dispatch ─────────────────────────────────
    pub fn waitAndDispatch(self: *Ring, handler: anytype) !void {
        _ = try self.ring.enter(0, 1, linux.IORING_ENTER_GETEVENTS);

        var cqes: [256]linux.io_uring_cqe = undefined;
        const n = try self.ring.copy_cqes(&cqes, 0);

        for (cqes[0..n]) |cqe| {
            const tag = tagFromUserdata(cqe.user_data);
            const fd = fdFromUserdata(cqe.user_data);
            const res = cqe.res;

            // Timeout CQEs return -ETIME which is normal — not an error
            if (tag == .timeout) {
                try handler.onTimeout();
                continue;
            }

            if (res < 0) {
                const e = std.posix.errno(@as(usize, @bitCast(@as(isize, res))));
                std.log.debug("CQE error fd={d} tag={s} err={s}", .{ fd, @tagName(tag), @tagName(e) });
                try handler.onError(fd, tag, e);
                continue;
            }

            switch (tag) {
                .accept => try handler.onAccept(fd, res),
                .recv => {
                    const buf_idx: u16 = @intCast(cqe.flags >> 16);
                    const data = self.bufferSlice(buf_idx, @intCast(res));
                    try handler.onRecv(fd, data, buf_idx);
                    self.recycleBuffer(buf_idx);
                },
                .send, .send_zc => try handler.onSend(fd, @intCast(res)),
                .close => try handler.onClose(fd),
                .connect => try handler.onConnect(fd, res >= 0),
                .timeout => unreachable, // handled above
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
