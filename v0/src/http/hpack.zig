/// http/hpack.zig — Full RFC 7541 HPACK implementation
///
/// Implements:
///   - Static table (61 entries, §Appendix A)
///   - Dynamic table with eviction (§2.3.2)
///   - Huffman encoding and decoding (§5.2, §Appendix B)
///   - All six representation types (§6)
///   - Table size update (§6.3)
///   - Sensitive headers (never-indexed, §7.1.3)
///
/// Thread safety: HpackEncoder and HpackDecoder each carry their own
/// dynamic table. They are NOT thread-safe — one per H2Conn, used only
/// on the owning worker thread.
const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// Huffman codec
// ─────────────────────────────────────────────────────────────────────────────

// RFC 7541 Appendix B — all 256 symbol codes + EOS (257)
// Each entry: {code: u32, bits: u5}
const HuffEntry = struct { code: u32, bits: u6 };

const HUFF_TABLE = [_]HuffEntry{
    .{ .code = 0x1ff8, .bits = 13 }, // 0
    .{ .code = 0x7fffd8, .bits = 23 }, // 1
    .{ .code = 0xfffffe2, .bits = 28 }, // 2
    .{ .code = 0xfffffe3, .bits = 28 }, // 3
    .{ .code = 0xfffffe4, .bits = 28 }, // 4
    .{ .code = 0xfffffe5, .bits = 28 }, // 5
    .{ .code = 0xfffffe6, .bits = 28 }, // 6
    .{ .code = 0xfffffe7, .bits = 28 }, // 7
    .{ .code = 0xfffffe8, .bits = 28 }, // 8
    .{ .code = 0xffffea, .bits = 24 }, // 9
    .{ .code = 0x3ffffffc, .bits = 30 }, // 10
    .{ .code = 0xfffffe9, .bits = 28 }, // 11
    .{ .code = 0xfffffea, .bits = 28 }, // 12
    .{ .code = 0x3ffffffd, .bits = 30 }, // 13
    .{ .code = 0xfffffeb, .bits = 28 }, // 14
    .{ .code = 0xfffffec, .bits = 28 }, // 15
    .{ .code = 0xfffffed, .bits = 28 }, // 16
    .{ .code = 0xfffffee, .bits = 28 }, // 17
    .{ .code = 0xfffffef, .bits = 28 }, // 18
    .{ .code = 0xffffff0, .bits = 28 }, // 19
    .{ .code = 0xffffff1, .bits = 28 }, // 20
    .{ .code = 0xffffff2, .bits = 28 }, // 21
    .{ .code = 0x3ffffffe, .bits = 30 }, // 22
    .{ .code = 0xffffff3, .bits = 28 }, // 23
    .{ .code = 0xffffff4, .bits = 28 }, // 24
    .{ .code = 0xffffff5, .bits = 28 }, // 25
    .{ .code = 0xffffff6, .bits = 28 }, // 26
    .{ .code = 0xffffff7, .bits = 28 }, // 27
    .{ .code = 0xffffff8, .bits = 28 }, // 28
    .{ .code = 0xffffff9, .bits = 28 }, // 29
    .{ .code = 0xffffffa, .bits = 28 }, // 30
    .{ .code = 0xffffffb, .bits = 28 }, // 31
    .{ .code = 0x14, .bits = 6 }, // ' ' (32)
    .{ .code = 0x3f8, .bits = 10 }, // '!' (33)
    .{ .code = 0x3f9, .bits = 10 }, // '"' (34)
    .{ .code = 0xffa, .bits = 12 }, // '#' (35)
    .{ .code = 0x1ff9, .bits = 13 }, // '$' (36)
    .{ .code = 0x15, .bits = 6 }, // '%' (37)
    .{ .code = 0xf8, .bits = 8 }, // '&' (38)
    .{ .code = 0x7fa, .bits = 11 }, // "'" (39)
    .{ .code = 0x3fa, .bits = 10 }, // '(' (40)
    .{ .code = 0x3fb, .bits = 10 }, // ')' (41)
    .{ .code = 0xf9, .bits = 8 }, // '*' (42)
    .{ .code = 0x7fb, .bits = 11 }, // '+' (43)
    .{ .code = 0xfa, .bits = 8 }, // ',' (44)
    .{ .code = 0x16, .bits = 6 }, // '-' (45)
    .{ .code = 0x17, .bits = 6 }, // '.' (46)
    .{ .code = 0x18, .bits = 6 }, // '/' (47)
    .{ .code = 0x0, .bits = 5 }, // '0' (48)
    .{ .code = 0x1, .bits = 5 }, // '1' (49)
    .{ .code = 0x2, .bits = 5 }, // '2' (50)
    .{ .code = 0x19, .bits = 6 }, // '3' (51)
    .{ .code = 0x1a, .bits = 6 }, // '4' (52)
    .{ .code = 0x1b, .bits = 6 }, // '5' (53)
    .{ .code = 0x1c, .bits = 6 }, // '6' (54)
    .{ .code = 0x1d, .bits = 6 }, // '7' (55)
    .{ .code = 0x1e, .bits = 6 }, // '8' (56)
    .{ .code = 0x1f, .bits = 6 }, // '9' (57)
    .{ .code = 0x5c, .bits = 7 }, // ':' (58)
    .{ .code = 0xfb, .bits = 8 }, // ';' (59)
    .{ .code = 0x7ffc, .bits = 15 }, // '<' (60)
    .{ .code = 0x20, .bits = 6 }, // '=' (61)
    .{ .code = 0xffb, .bits = 12 }, // '>' (62)
    .{ .code = 0x3fc, .bits = 10 }, // '?' (63)
    .{ .code = 0x1ffa, .bits = 13 }, // '@' (64)
    .{ .code = 0x21, .bits = 6 }, // 'A' (65)
    .{ .code = 0x5d, .bits = 7 }, // 'B' (66)
    .{ .code = 0x5e, .bits = 7 }, // 'C' (67)
    .{ .code = 0x5f, .bits = 7 }, // 'D' (68)
    .{ .code = 0x60, .bits = 7 }, // 'E' (69)
    .{ .code = 0x61, .bits = 7 }, // 'F' (70)
    .{ .code = 0x62, .bits = 7 }, // 'G' (71)
    .{ .code = 0x63, .bits = 7 }, // 'H' (72)
    .{ .code = 0x64, .bits = 7 }, // 'I' (73)
    .{ .code = 0x65, .bits = 7 }, // 'J' (74)
    .{ .code = 0x66, .bits = 7 }, // 'K' (75)
    .{ .code = 0x67, .bits = 7 }, // 'L' (76)
    .{ .code = 0x68, .bits = 7 }, // 'M' (77)
    .{ .code = 0x69, .bits = 7 }, // 'N' (78)
    .{ .code = 0x6a, .bits = 7 }, // 'O' (79)
    .{ .code = 0x6b, .bits = 7 }, // 'P' (80)
    .{ .code = 0x6c, .bits = 7 }, // 'Q' (81)
    .{ .code = 0x6d, .bits = 7 }, // 'R' (82)
    .{ .code = 0x6e, .bits = 7 }, // 'S' (83)
    .{ .code = 0x6f, .bits = 7 }, // 'T' (84)
    .{ .code = 0x70, .bits = 7 }, // 'U' (85)
    .{ .code = 0x71, .bits = 7 }, // 'V' (86)
    .{ .code = 0x72, .bits = 7 }, // 'W' (87)
    .{ .code = 0xfc, .bits = 8 }, // 'X' (88)
    .{ .code = 0x73, .bits = 7 }, // 'Y' (89)
    .{ .code = 0xfd, .bits = 8 }, // 'Z' (90)
    .{ .code = 0x1ffb, .bits = 13 }, // '[' (91)
    .{ .code = 0x7fff0, .bits = 19 }, // '\' (92)
    .{ .code = 0x1ffc, .bits = 13 }, // ']' (93)
    .{ .code = 0x3ffc, .bits = 14 }, // '^' (94)
    .{ .code = 0x22, .bits = 6 }, // '_' (95)
    .{ .code = 0x7ffd, .bits = 15 }, // '`' (96)
    .{ .code = 0x3, .bits = 5 }, // 'a' (97)
    .{ .code = 0x23, .bits = 6 }, // 'b' (98)
    .{ .code = 0x4, .bits = 5 }, // 'c' (99)
    .{ .code = 0x24, .bits = 6 }, // 'd' (100)
    .{ .code = 0x5, .bits = 5 }, // 'e' (101)
    .{ .code = 0x25, .bits = 6 }, // 'f' (102)
    .{ .code = 0x26, .bits = 6 }, // 'g' (103)
    .{ .code = 0x27, .bits = 6 }, // 'h' (104)
    .{ .code = 0x6, .bits = 5 }, // 'i' (105)
    .{ .code = 0x74, .bits = 7 }, // 'j' (106)
    .{ .code = 0x75, .bits = 7 }, // 'k' (107)
    .{ .code = 0x28, .bits = 6 }, // 'l' (108)
    .{ .code = 0x29, .bits = 6 }, // 'm' (109)
    .{ .code = 0x2a, .bits = 6 }, // 'n' (110)
    .{ .code = 0x7, .bits = 5 }, // 'o' (111)
    .{ .code = 0x2b, .bits = 6 }, // 'p' (112)
    .{ .code = 0x76, .bits = 7 }, // 'q' (113)
    .{ .code = 0x2c, .bits = 6 }, // 'r' (114)
    .{ .code = 0x8, .bits = 5 }, // 's' (115)
    .{ .code = 0x9, .bits = 5 }, // 't' (116)
    .{ .code = 0x2d, .bits = 6 }, // 'u' (117)
    .{ .code = 0x77, .bits = 7 }, // 'v' (118)
    .{ .code = 0x78, .bits = 7 }, // 'w' (119)
    .{ .code = 0x79, .bits = 7 }, // 'x' (120)
    .{ .code = 0x7a, .bits = 7 }, // 'y' (121)
    .{ .code = 0x7b, .bits = 7 }, // 'z' (122)
    .{ .code = 0x7ffe, .bits = 15 }, // '{' (123)
    .{ .code = 0x7fc, .bits = 11 }, // '|' (124)
    .{ .code = 0x3ffd, .bits = 14 }, // '}' (125)
    .{ .code = 0x1ffd, .bits = 13 }, // '~' (126)
    .{ .code = 0xffffffc, .bits = 28 }, // DEL (127)
    // 128-255: high bytes, all 25+ bits — abbreviated for space
    .{ .code = 0xfffe6, .bits = 20 }, // 128
    .{ .code = 0x3fffd2, .bits = 22 }, // 129
    .{ .code = 0xfffe7, .bits = 20 }, // 130
    .{ .code = 0xfffe8, .bits = 20 }, // 131
    .{ .code = 0x3fffd3, .bits = 22 }, // 132
    .{ .code = 0x3fffd4, .bits = 22 }, // 133
    .{ .code = 0x3fffd5, .bits = 22 }, // 134
    .{ .code = 0x7fffd9, .bits = 23 }, // 135
    .{ .code = 0x3fffd6, .bits = 22 }, // 136
    .{ .code = 0x7fffda, .bits = 23 }, // 137
    .{ .code = 0x7fffdb, .bits = 23 }, // 138
    .{ .code = 0x7fffdc, .bits = 23 }, // 139
    .{ .code = 0x7fffdd, .bits = 23 }, // 140
    .{ .code = 0x7fffde, .bits = 23 }, // 141
    .{ .code = 0xffffeb, .bits = 24 }, // 142
    .{ .code = 0x7fffdf, .bits = 23 }, // 143
    .{ .code = 0xffffec, .bits = 24 }, // 144
    .{ .code = 0xffffed, .bits = 24 }, // 145
    .{ .code = 0x3fffd7, .bits = 22 }, // 146
    .{ .code = 0x7fffe0, .bits = 23 }, // 147
    .{ .code = 0xffffee, .bits = 24 }, // 148
    .{ .code = 0x7fffe1, .bits = 23 }, // 149
    .{ .code = 0x7fffe2, .bits = 23 }, // 150
    .{ .code = 0x7fffe3, .bits = 23 }, // 151
    .{ .code = 0x7fffe4, .bits = 23 }, // 152
    .{ .code = 0x1fffdc, .bits = 21 }, // 153
    .{ .code = 0x3fffd8, .bits = 22 }, // 154
    .{ .code = 0x7fffe5, .bits = 23 }, // 155
    .{ .code = 0x3fffd9, .bits = 22 }, // 156
    .{ .code = 0x7fffe6, .bits = 23 }, // 157
    .{ .code = 0x7fffe7, .bits = 23 }, // 158
    .{ .code = 0xffffef, .bits = 24 }, // 159
    .{ .code = 0x3fffda, .bits = 22 }, // 160
    .{ .code = 0x1fffdd, .bits = 21 }, // 161
    .{ .code = 0xfffe9, .bits = 20 }, // 162
    .{ .code = 0x3fffdb, .bits = 22 }, // 163
    .{ .code = 0x3fffdc, .bits = 22 }, // 164
    .{ .code = 0x7fffe8, .bits = 23 }, // 165
    .{ .code = 0x7fffe9, .bits = 23 }, // 166
    .{ .code = 0x1fffde, .bits = 21 }, // 167
    .{ .code = 0x7fffea, .bits = 23 }, // 168
    .{ .code = 0x3fffdd, .bits = 22 }, // 169
    .{ .code = 0x3fffde, .bits = 22 }, // 170
    .{ .code = 0xfffff0, .bits = 24 }, // 171
    .{ .code = 0x1fffdf, .bits = 21 }, // 172
    .{ .code = 0x3fffdf, .bits = 22 }, // 173
    .{ .code = 0x7fffeb, .bits = 23 }, // 174
    .{ .code = 0x7fffec, .bits = 23 }, // 175
    .{ .code = 0x1fffe0, .bits = 21 }, // 176
    .{ .code = 0x1fffe1, .bits = 21 }, // 177
    .{ .code = 0x3fffe0, .bits = 22 }, // 178
    .{ .code = 0x1fffe2, .bits = 21 }, // 179
    .{ .code = 0x7fffed, .bits = 23 }, // 180
    .{ .code = 0x3fffe1, .bits = 22 }, // 181
    .{ .code = 0x7fffee, .bits = 23 }, // 182
    .{ .code = 0x7fffef, .bits = 23 }, // 183
    .{ .code = 0xfffea, .bits = 20 }, // 184
    .{ .code = 0x3fffe2, .bits = 22 }, // 185
    .{ .code = 0x3fffe3, .bits = 22 }, // 186
    .{ .code = 0x3fffe4, .bits = 22 }, // 187
    .{ .code = 0x7ffff0, .bits = 23 }, // 188
    .{ .code = 0x3fffe5, .bits = 22 }, // 189
    .{ .code = 0x3fffe6, .bits = 22 }, // 190
    .{ .code = 0x7ffff1, .bits = 23 }, // 191
    .{ .code = 0x3ffffe0, .bits = 26 }, // 192
    .{ .code = 0x3ffffe1, .bits = 26 }, // 193
    .{ .code = 0xfffeb, .bits = 20 }, // 194
    .{ .code = 0x7fff1, .bits = 19 }, // 195
    .{ .code = 0x3fffe7, .bits = 22 }, // 196
    .{ .code = 0x7ffff2, .bits = 23 }, // 197
    .{ .code = 0x3fffe8, .bits = 22 }, // 198
    .{ .code = 0x1ffffec, .bits = 25 }, // 199
    .{ .code = 0x3ffffe2, .bits = 26 }, // 200
    .{ .code = 0x3ffffe3, .bits = 26 }, // 201
    .{ .code = 0x3ffffe4, .bits = 26 }, // 202
    .{ .code = 0x7ffffde, .bits = 27 }, // 203
    .{ .code = 0x7ffffdf, .bits = 27 }, // 204
    .{ .code = 0x3ffffe5, .bits = 26 }, // 205
    .{ .code = 0xfffff1, .bits = 24 }, // 206
    .{ .code = 0x1ffffed, .bits = 25 }, // 207
    .{ .code = 0x7fff2, .bits = 19 }, // 208
    .{ .code = 0x1fffe3, .bits = 21 }, // 209
    .{ .code = 0x3ffffe6, .bits = 26 }, // 210
    .{ .code = 0x7ffffe0, .bits = 27 }, // 211
    .{ .code = 0x7ffffe1, .bits = 27 }, // 212
    .{ .code = 0x3ffffe7, .bits = 26 }, // 213
    .{ .code = 0x7ffffe2, .bits = 27 }, // 214
    .{ .code = 0xfffff2, .bits = 24 }, // 215
    .{ .code = 0x1fffe4, .bits = 21 }, // 216
    .{ .code = 0x1fffe5, .bits = 21 }, // 217
    .{ .code = 0x3ffffe8, .bits = 26 }, // 218
    .{ .code = 0x3ffffe9, .bits = 26 }, // 219
    .{ .code = 0xffffffd, .bits = 28 }, // 220
    .{ .code = 0x7ffffe3, .bits = 27 }, // 221
    .{ .code = 0x7ffffe4, .bits = 27 }, // 222
    .{ .code = 0x7ffffe5, .bits = 27 }, // 223
    .{ .code = 0xfffec, .bits = 20 }, // 224
    .{ .code = 0xfffff3, .bits = 24 }, // 225
    .{ .code = 0xfffed, .bits = 20 }, // 226
    .{ .code = 0x1fffe6, .bits = 21 }, // 227
    .{ .code = 0x3fffe9, .bits = 22 }, // 228
    .{ .code = 0x1fffe7, .bits = 21 }, // 229
    .{ .code = 0x1fffe8, .bits = 21 }, // 230
    .{ .code = 0x7ffff3, .bits = 23 }, // 231
    .{ .code = 0x3fffea, .bits = 22 }, // 232
    .{ .code = 0x3fffeb, .bits = 22 }, // 233
    .{ .code = 0x1ffffee, .bits = 25 }, // 234
    .{ .code = 0x1ffffef, .bits = 25 }, // 235
    .{ .code = 0xfffff4, .bits = 24 }, // 236
    .{ .code = 0xfffff5, .bits = 24 }, // 237
    .{ .code = 0x3ffffea, .bits = 26 }, // 238
    .{ .code = 0x7ffff4, .bits = 23 }, // 239
    .{ .code = 0x3ffffeb, .bits = 26 }, // 240
    .{ .code = 0x7ffffe6, .bits = 27 }, // 241
    .{ .code = 0x3ffffec, .bits = 26 }, // 242
    .{ .code = 0x3ffffed, .bits = 26 }, // 243
    .{ .code = 0x7ffffe7, .bits = 27 }, // 244
    .{ .code = 0x7ffffe8, .bits = 27 }, // 245
    .{ .code = 0x7ffffe9, .bits = 27 }, // 246
    .{ .code = 0x7ffffea, .bits = 27 }, // 247
    .{ .code = 0x7ffffeb, .bits = 27 }, // 248
    .{ .code = 0xffffffe, .bits = 28 }, // 249
    .{ .code = 0x7ffffec, .bits = 27 }, // 250
    .{ .code = 0x7ffffed, .bits = 27 }, // 251
    .{ .code = 0x7ffffee, .bits = 27 }, // 252
    .{ .code = 0x7ffffef, .bits = 27 }, // 253
    .{ .code = 0x7fffff0, .bits = 27 }, // 254
    .{ .code = 0x3ffffee, .bits = 26 }, // 255
    // EOS
    .{ .code = 0x3fffffff, .bits = 30 }, // 256 (EOS)
};

// ─────────────────────────────────────────────────────────────────────────────
// Huffman encoder
// ─────────────────────────────────────────────────────────────────────────────

/// Encode `src` using Huffman coding into `dst`.
/// Returns the number of bytes written.
pub fn huffmanEncode(src: []const u8, dst: []u8) usize {
    var bit_buf: u64 = 0;
    var bit_len: u7 = 0;
    var out: usize = 0;

    for (src) |byte| {
        const entry = HUFF_TABLE[byte];
        bit_buf = (bit_buf << @intCast(entry.bits)) | entry.code;
        bit_len += entry.bits;
        while (bit_len >= 8) {
            bit_len -= 8;
            dst[out] = @intCast((bit_buf >> bit_len) & 0xFF);
            out += 1;
        }
    }
    // Pad with EOS high bits (all 1s)
    if (bit_len > 0) {
        bit_buf = (bit_buf << @intCast(8 - bit_len)) | (0xFF >> @intCast(bit_len));
        dst[out] = @intCast(bit_buf & 0xFF);
        out += 1;
    }
    return out;
}

/// Upper bound on encoded length. Worst case: every byte expands to 30 bits.
pub fn huffmanEncodedLen(src: []const u8) usize {
    var bits: usize = 0;
    for (src) |byte| bits += HUFF_TABLE[byte].bits;
    return (bits + 7) / 8;
}

// ─────────────────────────────────────────────────────────────────────────────
// Huffman decoder — canonical table + accept/reject FSM
// ─────────────────────────────────────────────────────────────────────────────
//
// We use a 256-entry first-level lookup table where each entry covers one
// byte of input. For codes longer than 8 bits we chain into secondary tables.
// This is O(1) per decoded byte for codes ≤ 8 bits (most common HTTP headers)
// and O(n/8) for longer codes.
//
// Implementation: bit-by-bit decode — simpler to verify correct, and fast
// enough for header blocks (typically < 1 KB).

pub fn huffmanDecode(src: []const u8, dst: []u8) !usize {
    var state: u64 = 0;
    var bits: u7 = 0;
    var out: usize = 0;

    for (src) |byte| {
        var mask: u8 = 0x80;
        while (mask != 0) : (mask >>= 1) {
            state = (state << 1) | (if (byte & mask != 0) @as(u64, 1) else 0);
            bits += 1;

            // Try to match against the Huffman table
            for (HUFF_TABLE[0..256], 0..) |entry, sym| {
                if (entry.bits == bits and entry.code == @as(u32, @intCast(state))) {
                    if (out >= dst.len) return error.BufferTooSmall;
                    dst[out] = @intCast(sym);
                    out += 1;
                    state = 0;
                    bits = 0;
                    break;
                }
            } else {
                if (bits > 30) return error.InvalidHuffman;
            }
        }
    }

    // Remaining bits must be EOS padding (all 1s)
    if (bits > 0) {
        const mask: u64 = (@as(u64, 1) << bits) - 1;
        if ((state & mask) != mask) return error.InvalidHuffman;
    }

    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// HPACK static table
// ─────────────────────────────────────────────────────────────────────────────

pub const StaticEntry = struct { name: []const u8, value: []const u8 };

pub const STATIC_TABLE = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub const STATIC_TABLE_SIZE: usize = STATIC_TABLE.len;

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic table
// ─────────────────────────────────────────────────────────────────────────────
//
// RFC 7541 §2.3.2: entries are evicted FIFO from the oldest end.
// Size in "HPACK octets" = name.len + value.len + 32.
// Default max size = 4096 bytes; can be lowered by a SETTINGS_HEADER_TABLE_SIZE
// from the remote peer, communicated via a dynamic table size update.

const HPACK_ENTRY_OVERHEAD: usize = 32;

pub const DynamicEntry = struct {
    name: []u8,
    value: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DynamicEntry) void {
        self.allocator.free(self.name);
        self.allocator.free(self.value);
    }

    pub fn octets(self: *const DynamicEntry) usize {
        return self.name.len + self.value.len + HPACK_ENTRY_OVERHEAD;
    }
};

pub const DynamicTable = struct {
    entries: std.ArrayList(DynamicEntry), // index 0 = most recently added
    current_size: usize = 0,
    max_size: usize = 4096,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DynamicTable {
        return .{
            .entries = std.ArrayList(DynamicEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items) |*e| e.deinit();
        self.entries.deinit();
    }

    /// Add an entry, evicting oldest entries until the table fits max_size.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + HPACK_ENTRY_OVERHEAD;
        // If the entry itself exceeds max_size, evict everything (§2.3.2)
        if (entry_size > self.max_size) {
            self.evictAll();
            return;
        }
        while (self.current_size + entry_size > self.max_size) {
            self.evictOldest();
        }
        const e = DynamicEntry{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
            .allocator = self.allocator,
        };
        try self.entries.insert(0, e);
        self.current_size += entry_size;
    }

    pub fn setMaxSize(self: *DynamicTable, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size) {
            self.evictOldest();
        }
    }

    /// Look up entry at HPACK table index (1-based; static entries first).
    /// Returns null if index is out of range.
    pub fn getByIndex(self: *const DynamicTable, idx: usize) ?StaticEntry {
        if (idx == 0) return null;
        if (idx <= STATIC_TABLE_SIZE) {
            const e = STATIC_TABLE[idx - 1];
            return StaticEntry{ .name = e.name, .value = e.value };
        }
        const dyn_idx = idx - STATIC_TABLE_SIZE - 1;
        if (dyn_idx >= self.entries.items.len) return null;
        const e = &self.entries.items[dyn_idx];
        return StaticEntry{ .name = e.name, .value = e.value };
    }

    /// Find the best static+dynamic index for (name, value).
    /// Returns .{idx, exact} where exact=true means both name and value match.
    pub fn find(self: *const DynamicTable, name: []const u8, value: []const u8) struct { idx: usize, exact: bool } {
        var name_match: usize = 0;
        // Search static table
        for (STATIC_TABLE, 0..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                if (std.mem.eql(u8, entry.value, value)) return .{ .idx = i + 1, .exact = true };
                if (name_match == 0) name_match = i + 1;
            }
        }
        // Search dynamic table
        for (self.entries.items, 0..) |*entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                if (std.mem.eql(u8, entry.value, value)) return .{ .idx = STATIC_TABLE_SIZE + i + 1, .exact = true };
                if (name_match == 0) name_match = STATIC_TABLE_SIZE + i + 1;
            }
        }
        return .{ .idx = name_match, .exact = false };
    }

    fn evictOldest(self: *DynamicTable) void {
        if (self.entries.items.len == 0) return;
        var oldest = self.entries.pop();
        self.current_size -= oldest.octets();
        oldest.deinit();
    }

    fn evictAll(self: *DynamicTable) void {
        while (self.entries.items.len > 0) self.evictOldest();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HpackEncoder
// ─────────────────────────────────────────────────────────────────────────────

pub const HpackEncoder = struct {
    table: DynamicTable,
    out: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) HpackEncoder {
        return .{
            .table = DynamicTable.init(allocator),
            .out = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *HpackEncoder) void {
        self.table.deinit();
        self.out.deinit();
    }

    pub fn reset(self: *HpackEncoder) void {
        self.out.clearRetainingCapacity();
    }

    pub fn result(self: *const HpackEncoder) []const u8 {
        return self.out.items;
    }

    /// Update our encoding table's max size (after receiving SETTINGS).
    pub fn setMaxTableSize(self: *HpackEncoder, size: usize) void {
        self.table.setMaxSize(size);
    }

    /// Encode name:value. Sensitive headers (Authorization, Cookie, Set-Cookie)
    /// use literal-never-indexed (§7.1.3) so they don't enter the dynamic table.
    pub fn encodeHeader(self: *HpackEncoder, name: []const u8, value: []const u8) !void {
        const sensitive = isSensitive(name);

        if (!sensitive) {
            const found = self.table.find(name, value);
            if (found.exact) {
                // §6.1 Indexed Header Field
                try self.encodeInt(0x80, 7, found.idx);
                return;
            }
            if (found.idx != 0) {
                // §6.2.1 Literal With Incremental Indexing, indexed name
                try self.encodeInt(0x40, 6, found.idx);
            } else {
                // §6.2.1 Literal With Incremental Indexing, new name
                try self.out.append(0x40);
                try self.encodeStringHuffman(name);
            }
            try self.encodeStringHuffman(value);
            try self.table.insert(name, value);
        } else {
            // §6.2.3 Literal Never Indexed
            try self.out.append(0x10); // prefix 0001xxxx, index = 0
            try self.encodeStringHuffman(name);
            try self.encodeStringHuffman(value);
        }
    }

    /// Emit a dynamic table size update (§6.3). Call when remote SETTINGS arrives.
    pub fn emitTableSizeUpdate(self: *HpackEncoder, new_size: usize) !void {
        try self.encodeInt(0x20, 5, new_size);
    }

    fn encodeInt(self: *HpackEncoder, prefix: u8, n: u5, value: usize) !void {
        const max: usize = (@as(usize, 1) << n) - 1;
        if (value < max) {
            try self.out.append(prefix | @as(u8, @intCast(value)));
            return;
        }
        try self.out.append(prefix | @as(u8, @intCast(max)));
        var rem = value - max;
        while (rem >= 128) {
            try self.out.append(@as(u8, @intCast(rem & 0x7F)) | 0x80);
            rem >>= 7;
        }
        try self.out.append(@as(u8, @intCast(rem)));
    }

    fn encodeStringHuffman(self: *HpackEncoder, s: []const u8) !void {
        // Compute Huffman encoded length; only use if it saves bytes
        const hlen = huffmanEncodedLen(s);
        if (hlen < s.len) {
            try self.encodeInt(0x80, 7, hlen); // H=1
            const start = self.out.items.len;
            try self.out.resize(start + hlen);
            _ = huffmanEncode(s, self.out.items[start..]);
        } else {
            try self.encodeInt(0x00, 7, s.len); // H=0
            try self.out.appendSlice(s);
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HpackDecoder
// ─────────────────────────────────────────────────────────────────────────────

pub const DecodedHeader = struct {
    name: []u8,
    value: []u8,
    sensitive: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DecodedHeader) void {
        self.allocator.free(self.name);
        self.allocator.free(self.value);
    }
};

pub const HpackDecoder = struct {
    table: DynamicTable,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HpackDecoder {
        return .{ .table = DynamicTable.init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *HpackDecoder) void {
        self.table.deinit();
    }

    pub fn setMaxTableSize(self: *HpackDecoder, size: usize) void {
        self.table.setMaxSize(size);
    }

    /// Decode an HPACK block into `out`. Returns number of headers decoded.
    /// Each decoded header is heap-allocated; caller calls deinit on each.
    pub fn decode(self: *HpackDecoder, src: []const u8, out: []DecodedHeader) !usize {
        var pos: usize = 0;
        var count: usize = 0;

        while (pos < src.len and count < out.len) {
            const b = src[pos];

            if (b & 0x80 != 0) {
                // §6.1 Indexed Header Field
                const r = decodeInt(src, pos, 7);
                pos = r.next;
                const entry = self.table.getByIndex(r.value) orelse return error.InvalidIndex;
                out[count] = try self.makeHeader(entry.name, entry.value, false);
                count += 1;
            } else if (b & 0x40 != 0) {
                // §6.2.1 Literal with incremental indexing
                const r = decodeInt(src, pos, 6);
                pos = r.next;
                const name = if (r.value == 0) blk: {
                    const sr = try self.decodeString(src, pos);
                    pos = sr.next;
                    break :blk sr.str;
                } else blk: {
                    const entry = self.table.getByIndex(r.value) orelse return error.InvalidIndex;
                    break :blk try self.allocator.dupe(u8, entry.name);
                };
                errdefer self.allocator.free(name);
                const vr = try self.decodeString(src, pos);
                pos = vr.next;
                try self.table.insert(name, vr.str);
                out[count] = DecodedHeader{ .name = name, .value = vr.str, .sensitive = false, .allocator = self.allocator };
                count += 1;
            } else if (b & 0x20 != 0) {
                // §6.3 Dynamic table size update
                const r = decodeInt(src, pos, 5);
                pos = r.next;
                self.table.setMaxSize(r.value);
            } else {
                // §6.2.2 Literal without indexing / §6.2.3 never indexed
                const never_indexed = (b & 0x10) != 0;
                const r = decodeInt(src, pos, 4);
                pos = r.next;
                const name = if (r.value == 0) blk: {
                    const sr = try self.decodeString(src, pos);
                    pos = sr.next;
                    break :blk sr.str;
                } else blk: {
                    const entry = self.table.getByIndex(r.value) orelse return error.InvalidIndex;
                    break :blk try self.allocator.dupe(u8, entry.name);
                };
                errdefer self.allocator.free(name);
                const vr = try self.decodeString(src, pos);
                pos = vr.next;
                out[count] = DecodedHeader{ .name = name, .value = vr.str, .sensitive = never_indexed, .allocator = self.allocator };
                count += 1;
            }
        }
        return count;
    }

    const IntResult = struct { value: usize, next: usize };

    fn decodeInt(src: []const u8, pos: usize, n: u5) IntResult {
        const mask: u8 = (@as(u8, 1) << n) - 1;
        var value: usize = src[pos] & mask;
        var i = pos + 1;
        if (value < mask) return .{ .value = value, .next = i };
        var shift: u6 = 0;
        while (i < src.len) : (i += 1) {
            value += @as(usize, src[i] & 0x7F) << shift;
            shift += 7;
            if (src[i] & 0x80 == 0) {
                i += 1;
                break;
            }
        }
        return .{ .value = value, .next = i };
    }

    const StrResult = struct { str: []u8, next: usize };

    fn decodeString(self: *HpackDecoder, src: []const u8, pos: usize) !StrResult {
        const huffman = src[pos] & 0x80 != 0;
        const r = decodeInt(src, pos, 7);
        const data = src[r.next .. r.next + r.value];
        const str = if (huffman) blk: {
            // Allocate a worst-case buffer: Huffman never expands data
            const buf = try self.allocator.alloc(u8, data.len * 8); // generous upper bound
            errdefer self.allocator.free(buf);
            const decoded_len = try huffmanDecode(data, buf);
            const trimmed = try self.allocator.realloc(buf, decoded_len);
            break :blk trimmed;
        } else try self.allocator.dupe(u8, data);
        return StrResult{ .str = str, .next = r.next + r.value };
    }

    fn makeHeader(self: *HpackDecoder, name: []const u8, value: []const u8, sensitive: bool) !DecodedHeader {
        return DecodedHeader{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
            .sensitive = sensitive,
            .allocator = self.allocator,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn isSensitive(name: []const u8) bool {
    const sensitive_headers = [_][]const u8{
        "authorization", "proxy-authorization", "cookie",
        "set-cookie",    "www-authenticate",    "proxy-authenticate",
    };
    for (sensitive_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "huffman encode/decode round-trip" {
    const input = "www.example.com";
    var encoded: [64]u8 = undefined;
    const elen = huffmanEncode(input, &encoded);
    try std.testing.expect(elen < input.len); // Huffman should compress this
    var decoded: [64]u8 = undefined;
    const dlen = try huffmanDecode(encoded[0..elen], &decoded);
    try std.testing.expectEqualStrings(input, decoded[0..dlen]);
}

test "dynamic table insert and evict" {
    var table = DynamicTable.init(std.testing.allocator);
    defer table.deinit();
    table.setMaxSize(128);
    try table.insert("x-custom", "value1"); // 8+6+32 = 46
    try table.insert("x-other", "value2"); // 7+6+32 = 45 — total 91
    // third insert (46 bytes) → total 137 > 128 → evict oldest
    try table.insert("x-third", "value3");
    try std.testing.expect(table.entries.items.len == 2);
}

test "encoder/decoder round-trip with dynamic table" {
    var enc = HpackEncoder.init(std.testing.allocator);
    defer enc.deinit();
    var dec = HpackDecoder.init(std.testing.allocator);
    defer dec.deinit();

    enc.reset();
    try enc.encodeHeader(":method", "GET");
    try enc.encodeHeader(":path", "/api/users");
    try enc.encodeHeader("content-type", "application/json");
    try enc.encodeHeader("x-request-id", "abc123");

    var out: [16]DecodedHeader = undefined;
    const count = try dec.decode(enc.result(), &out);
    defer for (out[0..count]) |*h| h.deinit();

    try std.testing.expectEqual(@as(usize, 4), count);
    try std.testing.expectEqualStrings(":method", out[0].name);
    try std.testing.expectEqualStrings("GET", out[0].value);
    try std.testing.expectEqualStrings(":path", out[1].name);
    try std.testing.expectEqualStrings("/api/users", out[1].value);
    try std.testing.expectEqualStrings("x-request-id", out[3].name);
    try std.testing.expectEqualStrings("abc123", out[3].value);
}

test "sensitive headers never indexed" {
    var enc = HpackEncoder.init(std.testing.allocator);
    defer enc.deinit();
    enc.reset();
    try enc.encodeHeader("authorization", "Bearer secret");
    // First byte should be 0x10 (never indexed, new name)
    try std.testing.expectEqual(@as(u8, 0x10), enc.result()[0]);
    // Dynamic table should NOT have it
    try std.testing.expectEqual(@as(usize, 0), enc.table.entries.items.len);
}
