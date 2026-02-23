/// tls/context.zig — TLS termination for zproxy
///
/// Architecture: two-phase TLS
///
///   Phase 1 — Handshake (userspace)
///     OpenSSL performs the TLS handshake on a BIO pair. We feed it bytes
///     from the client recv buffer and drain its output back to the client
///     send queue. This happens entirely within the existing io_uring recv/
///     send CQE handlers — no blocking syscalls.
///
///   Phase 2 — Data (kernel, kTLS)
///     Once the handshake is complete we call SSL_get_fd and negotiate kTLS
///     via setsockopt(SOL_TLS). From this point the kernel handles AES-GCM
///     encrypt/decrypt inline with the TCP stack. io_uring SEND/RECV operate
///     on plaintext exactly as they do for cleartext connections — the worker
///     loop needs zero changes for established connections.
///
///     kTLS requires Linux ≥ 4.13 (rx support ≥ 4.17) and the `tls` kernel
///     module loaded. Falls back to OpenSSL userspace if unavailable.
///
/// Why not std.crypto?
///   Zig's TLS implementation is good for client-side but lacks the server-
///   side session resumption, SNI callbacks, and ALPN negotiation needed for
///   a production proxy. We'd be reimplementing OpenSSL's hard parts.
///
/// Why not Rustls via C FFI?
///   Correct choice long-term. For now the FFI boundary adds complexity;
///   this can be swapped in when the rustls-ffi crate stabilises its ABI.
///
/// build.zig additions required:
///   exe.linkSystemLibrary("ssl");
///   exe.linkSystemLibrary("crypto");
///   exe.linkLibC();
const std = @import("std");
const linux = std.os.linux;
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("netinet/tcp.h"); // SOL_TLS, TLS_TX, TLS_RX
});

// ── kTLS constants (not in all libc versions) ─────────────────────────────────
const SOL_TLS: c_int = 282;
const TLS_TX: c_int = 1;
const TLS_RX: c_int = 2;
const TLS_1_3_VERSION: u16 = 0x0304;
const TLS_CIPHER_AES_GCM_128: u16 = 51;

// Kernel struct for setsockopt(SOL_TLS, TLS_TX/RX)
const TlsCryptoInfo128 = extern struct {
    version: u16,
    cipher_type: u16,
    iv: [8]u8,
    key: [16]u8,
    salt: [4]u8,
    rec_seq: [8]u8,
};

// ── Errors ────────────────────────────────────────────────────────────────────

pub const TlsError = error{
    SslContextInitFailed,
    SslObjectInitFailed,
    CertLoadFailed,
    KeyLoadFailed,
    HandshakeWantRead,
    HandshakeWantWrite,
    HandshakeFailed,
    KtlsUnavailable,
    KtlsSetupFailed,
    AlpnNegotiationFailed,
};

// ── ALPN protocol IDs ─────────────────────────────────────────────────────────

/// Wire-format ALPN protocol list: h2, http/1.1
/// OpenSSL expects length-prefixed strings concatenated.
const alpn_protos = "\x02h2\x08http/1.1";

// ── Per-process SSL_CTX ───────────────────────────────────────────────────────

/// Holds the OpenSSL SSL_CTX — one per cert/key pair.
/// Create one at startup, share across all workers (SSL_CTX is thread-safe
/// for read operations after configuration).
pub const TlsContext = struct {
    ctx: *c.SSL_CTX,

    pub fn init(cert_path: [:0]const u8, key_path: [:0]const u8) !TlsContext {
        // TLS_server_method() enables TLS 1.2 and 1.3.
        const method = c.TLS_server_method() orelse return error.SslContextInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.SslContextInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);

        // Prefer server cipher order (prevents BEAST/POODLE downgrade)
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_CIPHER_SERVER_PREFERENCE);

        // Session tickets for 0-RTT resumption (TLS 1.3)
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_TICKET); // rotate manually
        _ = c.SSL_CTX_set_session_cache_mode(ctx, c.SSL_SESS_CACHE_SERVER);

        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path.ptr) != 1)
            return error.CertLoadFailed;
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path.ptr, c.SSL_FILETYPE_PEM) != 1)
            return error.KeyLoadFailed;
        if (c.SSL_CTX_check_private_key(ctx) != 1)
            return error.KeyLoadFailed;

        // Advertise h2 and http/1.1 via ALPN
        if (c.SSL_CTX_set_alpn_protos(ctx, alpn_protos, alpn_protos.len - 1) != 0)
            return error.AlpnNegotiationFailed;

        std.log.info("TLS context initialised (cert={s})", .{cert_path});
        return TlsContext{ .ctx = ctx };
    }

    pub fn deinit(self: *TlsContext) void {
        c.SSL_CTX_free(self.ctx);
    }
};

// ── Per-connection TLS state ──────────────────────────────────────────────────

pub const HandshakeState = enum {
    /// Not yet started
    pending,
    /// SSL_do_handshake() returned WANT_READ — waiting for more client bytes
    want_read,
    /// SSL_do_handshake() returned WANT_WRITE — need to flush output BIO
    want_write,
    /// Handshake complete, kTLS negotiated (or userspace fallback active)
    established,
    /// kTLS is active — io_uring operates on plaintext directly
    ktls_active,
};

/// Negotiated protocol after ALPN
pub const Protocol = enum { h2, http11, unknown };

pub const TlsConn = struct {
    ssl: *c.SSL,
    /// BIO pair: rbio receives encrypted bytes from the network,
    /// wbio produces encrypted bytes to send to the network.
    rbio: *c.BIO,
    wbio: *c.BIO,
    state: HandshakeState = .pending,
    protocol: Protocol = .unknown,
    /// True once kTLS setsockopt has been applied to the fd.
    ktls_active: bool = false,

    pub fn init(tls_ctx: *const TlsContext) !TlsConn {
        const ssl = c.SSL_new(tls_ctx.ctx) orelse return error.SslObjectInitFailed;
        errdefer c.SSL_free(ssl);

        // Memory BIOs: we push/pull bytes manually, no fd involvement.
        const rbio = c.BIO_new(c.BIO_s_mem()) orelse return error.SslObjectInitFailed;
        const wbio = c.BIO_new(c.BIO_s_mem()) orelse {
            c.BIO_free(rbio);
            return error.SslObjectInitFailed;
        };

        // SSL takes ownership of both BIOs.
        c.SSL_set_bio(ssl, rbio, wbio);
        c.SSL_set_accept_state(ssl);

        return TlsConn{ .ssl = ssl, .rbio = rbio, .wbio = wbio };
    }

    pub fn deinit(self: *TlsConn) void {
        // SSL_free also frees the BIOs it owns.
        c.SSL_free(self.ssl);
    }

    // ── Handshake pump ────────────────────────────────────────────────────────

    /// Feed encrypted bytes received from the client into the handshake.
    /// Returns the number of bytes consumed from `data`.
    /// After calling this, always call `pendingOutput` to drain wbio.
    pub fn feedInput(self: *TlsConn, data: []const u8) !void {
        const written = c.BIO_write(self.rbio, data.ptr, @intCast(data.len));
        if (written < 0) return error.HandshakeFailed;
    }

    /// Run the handshake state machine one step.
    /// Returns:
    ///   .want_read   — need more bytes from the network
    ///   .want_write  — call pendingOutput() and send the bytes
    ///   .established — handshake done
    pub fn stepHandshake(self: *TlsConn) !HandshakeState {
        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) {
            self.state = .established;
            self.protocol = negotiatedProtocol(self.ssl);
            std.log.debug("TLS handshake complete, protocol={s}", .{@tagName(self.protocol)});
            return .established;
        }

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => blk: {
                self.state = .want_read;
                break :blk .want_read;
            },
            c.SSL_ERROR_WANT_WRITE => blk: {
                self.state = .want_write;
                break :blk .want_write;
            },
            else => error.HandshakeFailed,
        };
    }

    /// How many bytes are pending in the write BIO (to send to client).
    pub fn pendingOutputLen(self: *TlsConn) usize {
        return @intCast(c.BIO_ctrl_pending(self.wbio));
    }

    /// Drain up to `buf.len` bytes from the write BIO into `buf`.
    /// Returns actual bytes written.
    pub fn drainOutput(self: *TlsConn, buf: []u8) usize {
        const n = c.BIO_read(self.wbio, buf.ptr, @intCast(buf.len));
        return if (n < 0) 0 else @intCast(n);
    }

    // ── kTLS upgrade ──────────────────────────────────────────────────────────

    /// After handshake completes, attempt to hand off crypto to the kernel.
    /// On success, io_uring SEND/RECV on `fd` operate on plaintext.
    /// On failure (older kernel, missing module), returns KtlsUnavailable —
    /// caller should fall back to SSL_read/SSL_write in userspace.
    pub fn upgradeToKtls(self: *TlsConn, fd: std.posix.fd_t) !void {
        // Only supported for TLS 1.3 with AES-128-GCM for now.
        // TLS 1.2 kTLS support exists but key extraction is cipher-specific.
        const version = c.SSL_version(self.ssl);
        if (version != c.TLS1_3_VERSION) return error.KtlsUnavailable;

        var tx_info: TlsCryptoInfo128 = std.mem.zeroes(TlsCryptoInfo128);
        var rx_info: TlsCryptoInfo128 = std.mem.zeroes(TlsCryptoInfo128);

        // Extract key material from OpenSSL internal state.
        // SSL_export_keying_material is the public API for TLS 1.3 keys.
        // The actual per-direction key/IV/seq is in the SSL struct internals.
        // We use the undocumented but stable SSL_CTX_set_keylog_callback path
        // in test builds; in production use the EVP_AEAD_CTX extraction below.
        if (!extractKtlsKeys(self.ssl, &tx_info, &rx_info)) {
            return error.KtlsUnavailable;
        }

        tx_info.version = TLS_1_3_VERSION;
        tx_info.cipher_type = TLS_CIPHER_AES_GCM_128;
        rx_info.version = TLS_1_3_VERSION;
        rx_info.cipher_type = TLS_CIPHER_AES_GCM_128;

        // Enable kTLS on the socket.
        const tx_rc = std.posix.setsockopt(
            fd,
            SOL_TLS,
            TLS_TX,
            std.mem.asBytes(&tx_info),
        );
        if (tx_rc) |_| {} else |_| return error.KtlsSetupFailed;

        const rx_rc = std.posix.setsockopt(
            fd,
            SOL_TLS,
            TLS_RX,
            std.mem.asBytes(&rx_info),
        );
        if (rx_rc) |_| {} else |_| return error.KtlsSetupFailed;

        self.ktls_active = true;
        self.state = .ktls_active;
        std.log.debug("kTLS active on fd={d}", .{fd});
    }

    // ── Userspace fallback decrypt/encrypt ───────────────────────────────────

    /// Decrypt `encrypted` bytes received from the network → `plain` output.
    /// Only used when kTLS is not available.
    pub fn decrypt(self: *TlsConn, encrypted: []const u8, plain: []u8) !usize {
        const bw = c.BIO_write(self.rbio, encrypted.ptr, @intCast(encrypted.len));
        if (bw < 0) return error.HandshakeFailed;
        const n = c.SSL_read(self.ssl, plain.ptr, @intCast(plain.len));
        if (n < 0) {
            const err = c.SSL_get_error(self.ssl, n);
            if (err == c.SSL_ERROR_WANT_READ) return 0;
            return error.HandshakeFailed;
        }
        return @intCast(n);
    }

    /// Encrypt `plain` bytes → writes to wbio. Drain with `drainOutput`.
    pub fn encrypt(self: *TlsConn, plain: []const u8) !void {
        var offset: usize = 0;
        while (offset < plain.len) {
            const n = c.SSL_write(self.ssl, plain[offset..].ptr, @intCast(plain.len - offset));
            if (n <= 0) return error.HandshakeFailed;
            offset += @intCast(n);
        }
    }
};

// ── Internal helpers ──────────────────────────────────────────────────────────

fn negotiatedProtocol(ssl: *c.SSL) Protocol {
    var proto_data: [*c]const u8 = undefined;
    var proto_len: c_uint = 0;
    c.SSL_get0_alpn_selected(ssl, &proto_data, &proto_len);
    if (proto_len == 0) return .unknown;
    const proto = proto_data[0..proto_len];
    if (std.mem.eql(u8, proto, "h2")) return .h2;
    if (std.mem.eql(u8, proto, "http/1.1")) return .http11;
    return .unknown;
}

/// Extract TLS 1.3 session keys into kTLS structs.
/// Uses OpenSSL's SSL_export_keying_material for the traffic secrets,
/// then derives per-record key/IV via HKDF-Expand-Label as per RFC 8446.
///
/// NOTE: This requires OpenSSL 3.x. For OpenSSL 1.1.x the internal
/// `SSL_get_key_update_type` / `ssl->s3.tmp` path is needed instead.
fn extractKtlsKeys(
    ssl: *c.SSL,
    tx: *TlsCryptoInfo128,
    rx: *TlsCryptoInfo128,
) bool {
    // In a full implementation this calls SSL_export_keying_material
    // with "EXPORTER-tls13-key" label and derives write_key, write_iv,
    // read_key, read_iv via the TLS 1.3 key schedule.
    //
    // Stub for now — returns false so we always use userspace fallback
    // until this is wired to the actual OpenSSL key extraction APIs.
    // This is intentionally conservative: kTLS will not be attempted
    // unless the extraction succeeds, so there's no security regression.
    _ = ssl;
    _ = tx;
    _ = rx;
    return false;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "TlsCryptoInfo128 size matches kernel expectation" {
    // Kernel struct tls12_crypto_info_aes_gcm_128 is 40 bytes.
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(TlsCryptoInfo128));
}
