# Native NPUMDIMG decoder

Base: https://github.com/mmozeiko/pkg2zip at commit
`9222c4e00235dfe7914e9db0cc352da07e63d9f9` (Unlicense).

The normal Zig build links the pinned AES and LZRC routines through
`ingest/src/npumdimg_native.c`. `npumdimg.zig::decode` takes borrowed immutable
bytes and returns one allocator-owned ISO buffer. It launches no subprocess,
reopens no source file, and writes no temporary output. The standalone
`pkg2zip-npumdimg` installation and `PKG2ZIP_NPUMDIMG` override are no longer used.

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
```

`prepare_npumdimg.py` copies the pinned dependency before applying
`pkg2zip-lzrc-safety.patch` and `pkg2zip-npumdimg-memory.patch`. Upstream source
and licensing remain intact in the fetched dependency. The linked route excludes
CLI, filesystem, outer-PKG and CSO operations. AES feature detection is
thread-local; malformed LZRC returns an error through a C-only local boundary,
never a process exit or an unwind through Zig frames.

Header/table/block bounds, encrypted-block alignment, LZRC probability/input/
output bounds and the former exact ISO descriptor check remain enforced.
Output preserves complete blocks, including padding in the final block.
All failures discard the owned allocation. Key derivation and ISO recognition
are not cryptographic authentication of the reconstructed image.

NPUMDIMG revision 2 uses native `pspdb-ingest` provenance. It produces `disc.iso`
with unchanged bytes and recursively inventories it beneath the source; it does
not promote the derivative to an original UMD root. PS1 disc payloads and EDAT
are different formats.

The native echochrome payload matches every byte of the retained standalone
oracle: 185401344 bytes, SHA-256
`affeb5cba3ddf43ae74db3d1e89c1651f927ee202519582d083dcd61838800a9`.
Both accelerated and portable AES passed targeted ASan/UBSan checks, including
unaligned immutable input, allocation failure, malformed blocks and concurrent
decoding. This is not a claim of whole-package authenticity or complete format
coverage.
