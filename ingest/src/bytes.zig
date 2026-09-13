const std = @import("std");

/// A view may borrow any subrange; retaining it keeps only its backing alive.
pub const View = struct {
    bytes: []const u8,
    owner: *Owner,

    pub fn retain(self: View) View {
        _ = self.owner.references.fetchAdd(1, .monotonic);
        return self;
    }

    pub fn release(self: View) void {
        self.owner.release();
    }
};

pub const Owner = struct {
    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize) = .init(1),
    storage: union(enum) {
        allocated: []u8,
        mapped: []align(std.heap.page_size_min) u8,
    },

    /// Consumes bytes on every path. The buffer must come from allocator.
    pub fn take_allocated(allocator: std.mem.Allocator, bytes: []u8) !View {
        errdefer allocator.free(bytes);
        const owner = try allocator.create(Owner);
        owner.* = .{ .allocator = allocator, .storage = .{ .allocated = bytes } };
        return .{ .owner = owner, .bytes = bytes };
    }

    /// Consumes the mapping on every path.
    pub fn take_mapped(allocator: std.mem.Allocator, bytes: []align(std.heap.page_size_min) u8) !View {
        errdefer std.posix.munmap(bytes);
        const owner = try allocator.create(Owner);
        owner.* = .{ .allocator = allocator, .storage = .{ .mapped = bytes } };
        return .{ .owner = owner, .bytes = bytes };
    }

    fn release(self: *Owner) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        switch (self.storage) {
            .allocated => |bytes| self.allocator.free(bytes),
            .mapped => |bytes| std.posix.munmap(bytes),
        }
        self.allocator.destroy(self);
    }
};

test "borrowed child survives parent; independent output releases separately" {
    const allocator = std.testing.allocator;
    const parent = try Owner.take_allocated(allocator, try allocator.dupe(u8, "parent bytes"));
    const child = (View{ .owner = parent.owner, .bytes = parent.bytes[7..] }).retain();
    parent.release();
    try std.testing.expectEqualStrings("bytes", child.bytes);
    const output = try Owner.take_allocated(allocator, try allocator.dupe(u8, child.bytes));
    child.release();
    defer output.release();
    try std.testing.expectEqualStrings("bytes", output.bytes);
}

test "failed adoption releases its consumed buffer" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const allocator = failing.allocator();
    const bytes = try allocator.dupe(u8, "owned buffer");
    try std.testing.expectError(error.OutOfMemory, Owner.take_allocated(allocator, bytes));
}
