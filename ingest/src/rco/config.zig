// INI semantics ported from RCOMage 54ca649a9a6aba150a1fbe423f4c3aec611ee913.
// Copyright (C) ZiNgA BuRgA; LGPL-2.1. Pinned configuration is immutable.
const std = @import("std");
const source = @import("rco_config");

pub const Kind = enum { int, float, ref, event, image, object, text, model, font, unk };
pub const Item = struct {
    name: []const u8,
    kind: Kind = .unk,
    pub fn is_ref(self: Item) bool {
        return switch (self.kind) {
            .int, .float, .unk => false,
            else => true,
        };
    }
};
const Section = struct { name: []const u8, start: usize, count: usize = 0, words: usize = 0 };
fn line_text(line: []const u8) []const u8 {
    return std.mem.trim(u8, line[0 .. std.mem.indexOfScalar(u8, line, ';') orelse line.len], " \t\r\n");
}
const Counts = struct { sections: usize, items: usize };
fn counts(comptime input: []const u8) Counts {
    @setEvalBranchQuota(1000000);
    var result: Counts = .{ .sections = 0, .items = 0 };
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw| {
        const line = line_text(raw);
        if (line.len == 0) continue;
        if (line[0] == '[') result.sections += 1 else result.items += 1;
    }
    return result;
}
fn Map(comptime input: []const u8) type {
    const n = counts(input);
    return struct {
        sections: [n.sections]Section,
        items: [n.items]Item,
        pub fn section(self: *const @This(), index: usize) ?Section {
            return if (index < self.sections.len) self.sections[index] else null;
        }
        pub fn entries(self: *const @This(), index: usize) ?[]const Item {
            const s = self.section(index) orelse return null;
            return self.items[s.start..][0..s.count];
        }
        pub fn named(self: *const @This(), name: []const u8) []const Item {
            for (self.sections, 0..) |s, i| if (std.ascii.eqlIgnoreCase(s.name, name)) return self.entries(i).?;
            unreachable;
        }
    };
}
fn parse(comptime input: []const u8, comptime typed: bool) Map(input) {
    @setEvalBranchQuota(1000000);
    var result: Map(input) = undefined;
    var section: usize = 0;
    var item: usize = 0;
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw| {
        const line = line_text(raw);
        if (line.len == 0) continue;
        if (line[0] == '[') {
            if (line[line.len - 1] != ']') @compileError("Invalid pinned RCO INI section");
            result.sections[section] = .{ .name = line[1 .. line.len - 1], .start = item };
            section += 1;
        } else {
            const equals = std.mem.indexOfScalar(u8, line, '=');
            const name = std.mem.trimEnd(u8, line[0 .. equals orelse line.len], " \t");
            const kind: Kind = if (typed) std.meta.stringToEnum(Kind, std.mem.trim(u8, line[(equals orelse @compileError("Missing pinned attribute type")) + 1 ..], " \t")) orelse @compileError("Unknown pinned attribute type") else .unk;
            const value: Item = .{ .name = name, .kind = kind };
            result.items[item] = value;
            item += 1;
            result.sections[section - 1].count += 1;
            result.sections[section - 1].words += if (value.is_ref()) @as(usize, 2) else 1;
        }
    }
    return result;
}
pub const tags = parse(source.tagmap, false);
pub const misc = parse(source.miscmap, false);
const obj_psp = parse(source.objattribdef_psp, true);
const obj_ps3 = parse(source.objattribdef_ps3, true);
const anim_psp = parse(source.animattribdef_psp, true);
const anim_ps3 = parse(source.animattribdef_ps3, true);
pub fn attributes(ps3: bool, id: u8, kind: u8) ?[]const Item {
    return if (id == 8)
        (if (ps3) obj_ps3.entries(kind) else obj_psp.entries(kind))
    else if (id == 9)
        (if (ps3) anim_ps3.entries(kind) else anim_psp.entries(kind))
    else
        null;
}
pub fn words(items: []const Item) usize {
    var result: usize = 0;
    for (items) |item| result += if (item.is_ref()) @as(usize, 2) else 1;
    return result;
}
