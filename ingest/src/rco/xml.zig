// Byte-preserving port of RCOMage xmlwrite.c and rcodump.c at
// 54ca649a9a6aba150a1fbe423f4c3aec611ee913. Copyright (C) ZiNgA BuRgA,
// LGPL-2.1. Encoding and XML acceptance use private libc/Expat contexts.
const std = @import("std");
const model = @import("model.zig");
const config = @import("config.zig");
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("locale.h");
    @cInclude("iconv.h");
    @cInclude("expat.h");
});
const Writer = std.Io.Writer;

pub fn validate(data: []const u8) !void {
    const parser = c.XML_ParserCreate(null) orelse return error.OutOfMemory;
    defer c.XML_ParserFree(parser);
    // Match ElementTree's Expat acceptance without a second DOM or a new
    // nesting limit. No external-entity handler is installed.
    var offset: usize = 0;
    while (true) {
        const size = @min(data.len - offset, std.math.maxInt(c_int));
        const final = offset + size == data.len;
        if (c.XML_Parse(parser, data[offset..].ptr, @intCast(size), @intFromBool(final)) != c.XML_STATUS_OK) {
            if (c.XML_GetErrorCode(parser) == c.XML_ERROR_NO_MEMORY) return error.OutOfMemory;
            return error.InvalidRcoXml;
        }
        if (final) break;
        offset += size;
    }
}
pub fn mapped(allocator: std.mem.Allocator, items: []const config.Item, number: usize) ![]const u8 {
    return if (number < items.len) items[number].name else std.fmt.allocPrint(allocator, "unknown0x{x}", .{number});
}
fn escaped(writer: *Writer, data: []const u8) !void {
    for (data) |byte| switch (byte) {
        '<' => try writer.writeAll("&lt;"),
        '>' => try writer.writeAll("&gt;"),
        '"' => try writer.writeAll("&quot;"),
        '&' => try writer.writeAll("&amp;"),
        '\n' => try writer.writeByte(byte),
        else => {
            // Upstream's Linux plain char is signed, including its decimal
            // entity behavior for bytes above 0x7f (post-parse rejects these).
            const signed: i8 = @bitCast(byte);
            if (signed < 32) try writer.print("&#{d};", .{signed}) else try writer.writeByte(byte);
        },
    };
}
fn indent(writer: *Writer, depth: usize) !void {
    try writer.splatByteAll('\t', depth);
}
fn tag_name(m: *const model.Model, entry: model.Entry) ![]const u8 {
    if (config.tags.section(entry.id)) |section| {
        const items = config.tags.entries(entry.id).?;
        if (entry.kind < items.len) return items[entry.kind].name;
        if (section.name.len != 0) return std.fmt.allocPrint(m.allocator, "{s}Unknown_0x{x}", .{ section.name, entry.kind });
    }
    return std.fmt.allocPrint(m.allocator, "Unknown_0x{x}_0x{x}", .{ entry.id, entry.kind });
}
fn value_map(m: *const model.Model, writer: *Writer, name: []const u8, section: []const u8, number: usize) !void {
    try writer.print(" {s}=\"{s}\"", .{ name, try mapped(m.allocator, config.misc.named(section), number) });
}
fn extra_attributes(m: *const model.Model, writer: *Writer, entry: model.Entry) !void {
    const attributes = config.attributes(m.ps3(), entry.id, entry.kind) orelse return error.InvalidRcoType;
    var pos: usize = 0;
    for (attributes) |attribute| {
        try writer.writeByte(' ');
        if (attribute.name.len != 0) try writer.writeAll(attribute.name) else {
            const suffix: []const u8 = switch (attribute.kind) {
                .float => "Float",
                .int => "Int",
                .event => "Event",
                .image => "Image",
                .model => "Model",
                .font => "Font",
                .object => "Object",
                .ref => "Ref",
                else => "",
            };
            try writer.print("unknown{s}{d}", .{ suffix, pos / 4 });
        }
        try writer.writeAll("=\"");
        if (attribute.is_ref()) {
            const reference = try m.reference(entry.extra, pos);
            try writer.writeAll(reference.prefix);
            try writer.writeAll(reference.value);
            pos += 8;
        } else {
            const word = try m.field_word(entry.extra, pos, attribute.kind);
            if (attribute.kind == .float) {
                var buf: [64]u8 = undefined;
                const value: f32 = @bitCast(word);
                const length = c.snprintf(&buf, buf.len, "%g", @as(f64, value));
                if (length < 0 or length >= buf.len) return error.InvalidRcoFloat;
                try writer.writeAll(buf[0..@intCast(length)]);
            } else try writer.print("0x{x}", .{word});
            pos += 4;
        }
        try writer.writeByte('"');
    }
}
fn open_entry(m: *const model.Model, writer: *Writer, entry: model.Entry) !void {
    const tag = try tag_name(m, entry);
    try indent(writer, entry.depth);
    try writer.print("<{s}", .{tag});
    if (entry.label != model.nil) {
        try writer.writeAll(" name=\"");
        try escaped(writer, try m.label(entry.label));
        try writer.writeByte('"');
    }
    if (entry.output_name.len != 0) try writer.print(" src=\"{s}\"", .{entry.output_name});
    const main_table = entry.kind == 0 or (entry.id == 1 and entry.kind == 1);
    if (!main_table) switch (entry.id) {
        2 => {},
        3 => {
            try value_map(m, writer, "language", "languages", entry.language);
            try value_map(m, writer, "format", "textformats", entry.format);
        },
        4, 5 => {
            try value_map(m, writer, "format", if (entry.id == 4) "imageformats" else "modelformats", entry.format);
            try value_map(m, writer, "compression", "compression", entry.compression);
            try writer.print(" unknownByte=\"{d}\"", .{entry.unknown_byte});
        },
        6 => {
            try value_map(m, writer, "format", "soundformats", entry.format);
            if (entry.format == 1) try writer.print(" channels=\"{d}\"", .{entry.channels.len});
        },
        7 => try writer.print(" unknownShort1=\"0x{x}\" unknownShort2=\"0x{x}\" unknownInt3=\"0x{x}\" unknownInt4=\"0x{x}\"", .{ try m.u16_at(entry.extra, 0), try m.u16_at(entry.extra, 2), try m.u32_at(entry.extra, 4), try m.u32_at(entry.extra, 8) }),
        8, 9 => try extra_attributes(m, writer, entry),
        else => {},
    };
    if (entry.children != 0) {
        try writer.writeAll(">\n");
    } else if (entry.id == 8 or entry.kind == 0 or (entry.kind == 1 and (entry.id == 9 or entry.id == 1 or entry.id == 2))) {
        try writer.print("></{s}>\n", .{tag});
    } else try writer.writeAll(" />\n");
}
pub fn structure(m: *const model.Model, allocator: std.mem.Allocator) ![]u8 {
    const locale = c.newlocale(c.LC_NUMERIC_MASK, "C", null) orelse return error.RcoLocaleUnavailable;
    defer c.freelocale(locale);
    const previous = c.uselocale(locale);
    if (previous == null) return error.RcoLocaleUnavailable;
    defer _ = c.uselocale(previous);
    var output: Writer.Allocating = .init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n<!-- This XML representation of an RCO structure was generated by Rcomage v1.1.1 -->\n");
    try writer.print("<RcoFile UMDFlag=\"{d}\" rcomageXmlVer=\"1.1\" type=\"{s}\"", .{ m.header[3] & 15, if (m.ps3()) @as([]const u8, "ps3") else "psp" });
    if (m.header[1] != 0) {
        try writer.writeAll(" minFirmwareVer=\"");
        switch (m.header[1]) {
            0x70 => try writer.writeAll("1.0"),
            0x71 => try writer.writeAll("1.5"),
            0x90 => try writer.writeAll("2.6"),
            0x95 => try writer.writeAll("2.7"),
            0x96 => try writer.writeAll("2.8"),
            0x100 => try writer.writeAll("3.5"),
            else => try writer.print("unknownId0x{x}", .{m.header[1]}),
        }
        try writer.writeByte('"');
    }
    try writer.writeAll(">\n");
    for (m.entries.items, 0..) |entry, index| {
        try open_entry(m, writer, entry);
        if (entry.children != 0) continue;
        var parent = entry.parent;
        while (parent) |p| {
            const ancestor = m.entries.items[p];
            if (ancestor.end != index + 1) break;
            try indent(writer, ancestor.depth);
            try writer.print("</{s}>\n", .{try tag_name(m, ancestor)});
            parent = ancestor.parent;
        }
    }
    try writer.writeAll("</RcoFile>\n");
    return output.toOwnedSlice();
}
pub fn language(m: *const model.Model, allocator: std.mem.Allocator, entry: model.Entry) ![]u8 {
    const encoding: [*:0]const u8 = switch (entry.format) {
        0 => "utf-8",
        1 => if (m.ps3()) "ucs-2be" else "ucs-2le",
        2 => if (m.ps3()) "ucs-4be" else "ucs-4le",
        else => return error.InvalidRcoText,
    };
    const converter = c.iconv_open("utf-8", encoding);
    if (converter == @as(c.iconv_t, @ptrFromInt(std.math.maxInt(usize)))) return error.InvalidRcoEncoding;
    defer _ = c.iconv_close(converter);
    var output: Writer.Allocating = .init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- This XML was generated by Rcomage v1.1.1 -->\n<TextLang>\n");
    const data = if (entry.source) |view| view.bytes else &.{};
    const width: usize = @as(usize, 1) << @intCast(entry.format);
    for (entry.indexes) |index| {
        var text: []const u8 = if (index.length == 0) &.{} else try model.region(data, index.offset, index.length);
        if (text.len >= width and std.mem.allEqual(u8, text[text.len - width ..], 0)) text = text[0 .. text.len - width];
        const cdata = std.mem.indexOfAny(u8, text, "<>&") != null;
        try writer.print("\t<Text name=\"{s}\">", .{try m.resource_label(index.label)});
        if (cdata) try writer.writeAll("<![CDATA[");
        var input_ptr: [*c]u8 = @constCast(text.ptr);
        var remaining = text.len;
        while (remaining != 0) {
            var buffer: [4096]u8 = undefined;
            var out_ptr: [*c]u8 = &buffer;
            var available: usize = buffer.len;
            const old_remaining = remaining;
            _ = c.iconv(converter, &input_ptr, &remaining, &out_ptr, &available);
            const written = buffer.len - available;
            if (written == 0 or remaining >= old_remaining) return error.InvalidRcoEncoding;
            const bytes = buffer[0..written];
            if (std.mem.indexOfScalar(u8, bytes, 0) != null) return error.InvalidRcoTextNull;
            try writer.writeAll(bytes);
        }
        if (cdata) try writer.writeAll("]]>");
        try writer.writeAll("</Text>\n");
    }
    try writer.writeAll("</TextLang>\n");
    return output.toOwnedSlice();
}
