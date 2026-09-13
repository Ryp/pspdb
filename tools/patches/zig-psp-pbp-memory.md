# Zig-PSP PBP memory API

Base: `zPSP-Dev/Zig-PSP` commit `35a7e02f1a2eafc200a851aea1ed0757128fe28e`,
pinned with its Zig package hash in `ingest/build.zig.zon`.

`zig-psp-pbp-memory.patch` refactors the dependency's zPBPTool reader into
`Pbp.parse(bytes)`, `walk`, and `get`. Both upstream CLI operations (analyze and
unpack) use that same parser. Sections borrow the input buffer; parsing and
walking allocate nothing and perform no filesystem operations.

The patch also fixes these issues in the pinned upstream unpacker:

- Final-section length used the post-header buffer size with a whole-file offset,
  truncating DATA.PSAR by 40 bytes.
- Reversed/out-of-bounds offsets could silently omit sections or panic.
- Signature validation ignored the first byte.
- Unpacking leaked the allocated input and output filenames when used as a library.

Upstream version acceptance is preserved: the real echochrome demo uses PBP 1.1.

The build applies the patch to a generated copy of the dependency source and
imports it as `zig_psp_pbp`; it does not modify the dependency cache or the local
Zig-PSP checkout. GNU `patch` must be on PATH. No SDK binaries are needed at runtime.

`ingest/src/containers.zig` only adapts the upstream API and error type. PKG
metadata extraction uses the same API. Tests check borrowed-slice identity,
complete final-section bytes, malformed headers/ranges, and nested ingest.

PBP extraction records `Zig-PSP zPBPTool` / `in-memory` provenance. PKG extraction
uses this reader for embedded metadata. Bump their revisions when changing the
dependency/patch in ways that affect results. This patch is local, not yet submitted upstream.

The reader names the final section `DATA.BIN` in the tool's analyzer, unpacker
and memory API. The PBP stores offsets, not filenames; this neutral generated
name avoids implying that the payload is always a firmware PSAR archive. Format
detection continues to inspect the bytes.
