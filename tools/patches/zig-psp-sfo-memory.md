# Zig-PSP SFO memory API

Uses the same Zig-PSP commit pinned in `ingest/build.zig.zon`:
`35a7e02f1a2eafc200a851aea1ed0757128fe28e`.

The upstream `tools/sfo/src/main.zig` reader is private and takes a filename.
`zig-psp-sfo-memory.patch` exposes `readSFO(allocator, bytes)` using a fixed
in-memory reader. It retains upstream's SFOHeader, TableEntry, TableDataType,
and SFOStructure. Only the decoded entry table is allocated; key/data pools
borrow the input and remain valid after the table is freed with `deinit`.
The CLI pretty-printer calls this same reader after loading its input file.

The patch replaces the reader's assertion with bounded validation of the header,
entry count, pools, keys, and entry ranges. Unknown field formats are represented
by a non-exhaustive enum. Bounded key/data accessors expose the parsed entries.
No extraction files, subprocesses, or separate SFO binary parser are used by ingest.

`ingest/src/sfo.zig` selects DISC_ID, DISC_VERSION, TITLE, and PSP_SYSTEM_VER
from those entries. It retains PSPDB's metadata rules: selected fields must be
UTF-8 strings, terminated, and nonduplicated. Missing metadata stays optional.
This code is a catalog adapter, not another binary structure reader.

The build applies the patch to a generated copy of the pinned dependency;
neither the dependency cache nor the user's separate Zig-PSP checkout is changed.
The patch is local and has not been submitted upstream. An upstream memory API
would let us remove this patch.
