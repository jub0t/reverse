/// toml.zig — minimal TOML 1.0 parser
///
/// Supports the subset needed by zproxy:
///   • [table] and [[array of tables]]
///   • string, integer, float, boolean values
///   • inline arrays of strings: ["a", "b"]
///   • dotted keys: a.b.c = "val"
///   • # comments
///   • Multi-line NOT supported (not needed)
///
/// Usage:
///   var doc = try toml.parse(allocator, src);
///   defer doc.deinit();
///   const port = doc.getInt("server[0].port") orelse 8080;
///   const name = doc.getString("server[0].server_name[0]") orelse "";
const std = @import("std");

// ── Value types ───────────────────────────────────────────────────────────────

pub const ValueTag = enum { string, integer, float, boolean, array, table };

pub const Value = union(ValueTag) {
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,
    array: std.ArrayList(Value),
    table: Table,

    pub fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |s| allocator.free(s),
            .array => |*a| {
                for (a.items) |*v| v.deinit(allocator);
                a.deinit();
            },
            .table => |*t| t.deinit(allocator),
            else => {},
        }
    }
};

pub const Table = struct {
    map: std.StringHashMap(Value),

    pub fn init(allocator: std.mem.Allocator) Table {
        return .{ .map = std.StringHashMap(Value).init(allocator) };
    }

    pub fn deinit(self: *Table, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.map.deinit();
    }

    pub fn get(self: *const Table, key: []const u8) ?*Value {
        return self.map.getPtr(key);
    }
};

// ── Document — top-level accessor ─────────────────────────────────────────────

pub const Document = struct {
    root: Table,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Document) void {
        self.root.deinit(self.allocator);
    }

    /// Navigate a dotted path like "server[0].upstream_pool[1].name"
    /// Returns null if any segment is missing or the wrong type.
    pub fn getValue(self: *const Document, path: []const u8) ?*Value {
        return navigatePath(&self.root, path);
    }

    pub fn getString(self: *const Document, path: []const u8) ?[]const u8 {
        const v = self.getValue(path) orelse return null;
        return if (v.* == .string) v.string else null;
    }

    pub fn getInt(self: *const Document, path: []const u8) ?i64 {
        const v = self.getValue(path) orelse return null;
        return if (v.* == .integer) v.integer else null;
    }

    pub fn getFloat(self: *const Document, path: []const u8) ?f64 {
        const v = self.getValue(path) orelse return null;
        return if (v.* == .float) v.float else null;
    }

    pub fn getBool(self: *const Document, path: []const u8) ?bool {
        const v = self.getValue(path) orelse return null;
        return if (v.* == .boolean) v.boolean else null;
    }

    /// Return the length of an array at path, or 0.
    pub fn arrayLen(self: *const Document, path: []const u8) usize {
        const v = self.getValue(path) orelse return 0;
        return if (v.* == .array) v.array.items.len else 0;
    }
};

fn navigatePath(table: *const Table, path: []const u8) ?*Value {
    if (path.len == 0) return null;

    // Find first separator: '.' or '['
    var seg_end = path.len;
    var next_start = path.len;
    var array_idx: ?usize = null;

    for (path, 0..) |c, i| {
        if (c == '.') {
            seg_end = i;
            next_start = i + 1;
            break;
        }
        if (c == '[') {
            seg_end = i;
            // parse index up to ']'
            const close = std.mem.indexOfScalarPos(u8, path, i, ']') orelse return null;
            array_idx = std.fmt.parseInt(usize, path[i + 1 .. close], 10) catch return null;
            next_start = if (close + 1 < path.len and path[close + 1] == '.') close + 2 else close + 1;
            break;
        }
    }

    const key = path[0..seg_end];
    const val = table.map.getPtr(key) orelse return null;

    if (array_idx) |idx| {
        if (val.* != .array) return null;
        if (idx >= val.array.items.len) return null;
        const elem = &val.array.items[idx];
        if (next_start >= path.len) return elem;
        if (elem.* != .table) return null;
        return navigatePath(&elem.table, path[next_start..]);
    }

    if (next_start >= path.len) return val;
    if (val.* != .table) return null;
    return navigatePath(&val.table, path[next_start..]);
}

// ── Parser ────────────────────────────────────────────────────────────────────

const Parser = struct {
    src: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,
    root: Table,
    /// Current table being written into (pointer into root tree)
    cur: *Table,
    /// Path of the current [[array of tables]] context, or empty
    cur_array_path: []const []const u8,

    fn init(allocator: std.mem.Allocator, src: []const u8) !Parser {
        var root = Table.init(allocator);
        return Parser{
            .src = src,
            .pos = 0,
            .allocator = allocator,
            .root = root,
            .cur = &root, // will be fixed after return
            .cur_array_path = &.{},
        };
    }

    // ── character helpers ─────────────────────────────────────────────────

    fn peek(self: *Parser) ?u8 {
        if (self.pos >= self.src.len) return null;
        return self.src[self.pos];
    }

    fn advance(self: *Parser) void {
        if (self.pos < self.src.len) self.pos += 1;
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.peek()) |c| {
            if (c == ' ' or c == '\t' or c == '\r') {
                self.advance();
            } else break;
        }
    }

    fn skipLine(self: *Parser) void {
        while (self.peek()) |c| {
            self.advance();
            if (c == '\n') break;
        }
    }

    fn skipWhitespaceAndComments(self: *Parser) void {
        while (true) {
            self.skipWhitespace();
            const c = self.peek() orelse break;
            if (c == '#') {
                self.skipLine();
            } else if (c == '\n') {
                self.advance();
            } else break;
        }
    }

    // ── key parsing ───────────────────────────────────────────────────────

    fn parseKey(self: *Parser) ![]const u8 {
        self.skipWhitespace();
        const c = self.peek() orelse return error.UnexpectedEof;
        if (c == '"') return self.parseString();
        // bare key: a-z A-Z 0-9 - _
        const start = self.pos;
        while (self.peek()) |ch| {
            if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_') {
                self.advance();
            } else break;
        }
        if (self.pos == start) return error.EmptyKey;
        return try self.allocator.dupe(u8, self.src[start..self.pos]);
    }

    // ── value parsing ─────────────────────────────────────────────────────

    const ParseError = error{
        UnexpectedEof,
        UnexpectedChar,
        ExpectedQuote,
        UnterminatedString,
        InvalidEscape,
        InvalidBool,
        ExpectedBracket,
        InvalidInt,
        InvalidFloat,
        OutOfMemory,
    };

    fn parseValue(self: *Parser) ParseError!Value {
        self.skipWhitespace();
        const c = self.peek() orelse return error.UnexpectedEof;
        return switch (c) {
            '"' => Value{ .string = try self.parseString() },
            '[' => Value{ .array = try self.parseInlineArray() },
            't', 'f' => Value{ .boolean = try self.parseBool() },
            '-', '0'...'9' => try self.parseNumber(),
            else => error.UnexpectedChar,
        };
    }

    fn parseString(self: *Parser) ParseError![]const u8 {
        if (self.peek() != '"') return error.ExpectedQuote;
        self.advance();
        var buf = std.ArrayList(u8).init(self.allocator);
        errdefer buf.deinit();
        while (true) {
            const c = self.peek() orelse return error.UnterminatedString;
            if (c == '"') {
                self.advance();
                break;
            }
            if (c == '\\') {
                self.advance();
                const esc = self.peek() orelse return error.UnterminatedString;
                self.advance();
                try buf.append(switch (esc) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '"' => '"',
                    '\\' => '\\',
                    else => return error.InvalidEscape,
                });
            } else {
                try buf.append(c);
                self.advance();
            }
        }
        return buf.toOwnedSlice();
    }

    fn parseBool(self: *Parser) ParseError!bool {
        if (std.mem.startsWith(u8, self.src[self.pos..], "true")) {
            self.pos += 4;
            return true;
        }
        if (std.mem.startsWith(u8, self.src[self.pos..], "false")) {
            self.pos += 5;
            return false;
        }
        return error.InvalidBool;
    }

    fn parseNumber(self: *Parser) ParseError!Value {
        const start = self.pos;
        var is_float = false;
        if (self.peek() == '-') self.advance();
        while (self.peek()) |c| {
            if (std.ascii.isDigit(c)) {
                self.advance();
            } else if (c == '.' or c == 'e' or c == 'E') {
                is_float = true;
                self.advance();
            } else break;
        }
        const s = self.src[start..self.pos];
        if (is_float) {
            return Value{ .float = std.fmt.parseFloat(f64, s) catch return error.InvalidFloat };
        } else {
            return Value{ .integer = std.fmt.parseInt(i64, s, 10) catch return error.InvalidInt };
        }
    }

    fn parseInlineArray(self: *Parser) ParseError!std.ArrayList(Value) {
        if (self.peek() != '[') return error.ExpectedBracket;
        self.advance();
        var arr = std.ArrayList(Value).init(self.allocator);
        errdefer {
            for (arr.items) |*v| v.deinit(self.allocator);
            arr.deinit();
        }
        while (true) {
            self.skipWhitespaceAndComments();
            if (self.peek() == ']') {
                self.advance();
                break;
            }
            var val: Value = try self.parseValue();
            errdefer val.deinit(self.allocator);
            try arr.append(val);
            self.skipWhitespace();
            if (self.peek() == ',') self.advance();
        }
        return arr;
    }

    // ── table header: [key] or [[key]] ────────────────────────────────────

    fn parseTableHeader(self: *Parser) !struct { path: [][]const u8, is_array: bool } {
        var is_array = false;
        self.advance(); // consume first [
        if (self.peek() == '[') {
            is_array = true;
            self.advance();
        }
        self.skipWhitespace();

        var segments = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (segments.items) |s| self.allocator.free(s);
            segments.deinit();
        }

        while (true) {
            const seg = try self.parseKey();
            try segments.append(seg);
            self.skipWhitespace();
            if (self.peek() == '.') {
                self.advance();
            } else break;
        }

        self.skipWhitespace();
        if (self.peek() != ']') return error.ExpectedCloseBracket;
        self.advance();
        if (is_array) {
            if (self.peek() != ']') return error.ExpectedCloseBracket;
            self.advance();
        }
        self.skipLine();

        return .{ .path = try segments.toOwnedSlice(), .is_array = is_array };
    }

    // ── navigate/create path in root table ───────────────────────────────

    /// Walk path segments into root, creating tables as needed.
    /// For array-of-tables paths, appends a new table and returns ptr to it.
    fn resolvePath(self: *Parser, segments: []const []const u8, is_array: bool) !*Table {
        var cur: *Table = &self.root;
        const last = segments.len - 1;

        for (segments, 0..) |seg, i| {
            const is_last = (i == last);

            if (cur.map.getPtr(seg)) |existing| {
                if (is_last and is_array) {
                    // [[array]] — append new table to existing array
                    if (existing.* != .array) return error.TypeConflict;
                    const new_table = Table.init(self.allocator);
                    try existing.array.append(Value{ .table = new_table });
                    const arr_len = existing.array.items.len;
                    return &existing.array.items[arr_len - 1].table;
                } else if (existing.* == .table) {
                    cur = &existing.table;
                } else if (existing.* == .array) {
                    // navigate into last element
                    const arr_len = existing.array.items.len;
                    if (arr_len == 0) return error.EmptyArray;
                    cur = &existing.array.items[arr_len - 1].table;
                } else {
                    return error.TypeConflict;
                }
            } else {
                // create new entry
                const key = try self.allocator.dupe(u8, seg);
                if (is_last and is_array) {
                    var arr = std.ArrayList(Value).init(self.allocator);
                    const new_table = Table.init(self.allocator);
                    try arr.append(Value{ .table = new_table });
                    try cur.map.put(key, Value{ .array = arr });
                    const val = cur.map.getPtr(key).?;
                    return &val.array.items[0].table;
                } else {
                    const new_table = Table.init(self.allocator);
                    try cur.map.put(key, Value{ .table = new_table });
                    cur = &cur.map.getPtr(key).?.table;
                }
            }
        }
        return cur;
    }

    // ── main parse loop ───────────────────────────────────────────────────

    fn parse(self: *Parser) !Document {
        // Fix up self.cur to point at root (can't take address before return)
        self.cur = &self.root;

        while (true) {
            self.skipWhitespaceAndComments();
            const c = self.peek() orelse break;

            if (c == '[') {
                const header = try self.parseTableHeader();
                defer {
                    for (header.path) |s| self.allocator.free(s);
                    self.allocator.free(header.path);
                }
                self.cur = try self.resolvePath(header.path, header.is_array);
            } else {
                // key = value
                const key = try self.parseKey();
                errdefer self.allocator.free(key);
                self.skipWhitespace();
                if (self.peek() != '=') return error.ExpectedEquals;
                self.advance();
                var val = try self.parseValue();
                errdefer val.deinit(self.allocator);
                self.skipWhitespace();
                // allow trailing comment
                if (self.peek() == '#') self.skipLine();
                if (self.peek()) |nl| {
                    if (nl != '\n' and nl != '\r') return error.ExpectedNewline;
                }
                // put into current table (may already exist for dotted keys)
                if (self.cur.map.contains(key)) {
                    self.allocator.free(key);
                    val.deinit(self.allocator);
                    return error.DuplicateKey;
                }
                try self.cur.map.put(key, val);
            }
        }

        return Document{
            .root = self.root,
            .allocator = self.allocator,
        };
    }
};

pub fn parse(allocator: std.mem.Allocator, src: []const u8) !Document {
    var p = try Parser.init(allocator, src);
    return p.parse();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "basic key-value" {
    const src =
        \\port = 8080
        \\name = "zproxy"
        \\debug = true
    ;
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit();

    try std.testing.expectEqual(@as(?i64, 8080), doc.getInt("port"));
    try std.testing.expectEqualStrings("zproxy", doc.getString("name").?);
    try std.testing.expectEqual(@as(?bool, true), doc.getBool("debug"));
}

test "table section" {
    const src =
        \\[server]
        \\port = 9090
        \\bind = "127.0.0.1"
    ;
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit();

    try std.testing.expectEqual(@as(?i64, 9090), doc.getInt("server.port"));
    try std.testing.expectEqualStrings("127.0.0.1", doc.getString("server.bind").?);
}

test "array of tables" {
    const src =
        \\[[server]]
        \\port = 8080
        \\
        \\[[server]]
        \\port = 9090
    ;
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit();

    try std.testing.expectEqual(@as(?i64, 8080), doc.getInt("server[0].port"));
    try std.testing.expectEqual(@as(?i64, 9090), doc.getInt("server[1].port"));
}

test "inline string array" {
    const src =
        \\names = ["example.com", "www.example.com"]
    ;
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit();

    try std.testing.expectEqual(@as(usize, 2), doc.arrayLen("names"));
    try std.testing.expectEqualStrings("example.com", doc.getString("names[0]").?);
    try std.testing.expectEqualStrings("www.example.com", doc.getString("names[1]").?);
}

test "nested array of tables" {
    const src =
        \\[[server]]
        \\port = 8080
        \\
        \\  [[server.upstream_pool]]
        \\  name = "api"
        \\
        \\  [[server.upstream_pool]]
        \\  name = "static"
    ;
    var doc = try parse(std.testing.allocator, src);
    defer doc.deinit();

    try std.testing.expectEqualStrings("api", doc.getString("server[0].upstream_pool[0].name").?);
    try std.testing.expectEqualStrings("static", doc.getString("server[0].upstream_pool[1].name").?);
}
