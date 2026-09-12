# pkg2zip standalone NPUMDIMG decoder

Base: https://github.com/mmozeiko/pkg2zip at commit
`9222c4e00235dfe7914e9db0cc352da07e63d9f9` (Unlicense).

The patch exposes the existing `unpack_psp_eboot` decoder through a separate
`pkg2zip-npumdimg SOURCE OUTPUT.iso` executable. A null PKG key selects an already
extracted NPUMDIMG input; it skips only the outer PKG/PBP handling. PSP crypto,
block-table interpretation and LZRC decompression remain pkg2zip's implementation.
The original pkg2zip entry point remains supported.

Additional checks reject truncated headers/tables/blocks, zero block size,
invalid sector ranges, unaligned encrypted blocks and LZRC input/probability/output
bounds. Codec failures exit the subprocess and prevent publishing the input root.
No new Zig crypto or decompression implementation is introduced.

From the repository root, on Linux with Git, GNU patch, make and a C compiler:

```sh
git clone https://github.com/mmozeiko/pkg2zip .work/pkg2zip
git -C .work/pkg2zip checkout 9222c4e00235dfe7914e9db0cc352da07e63d9f9
patch -d .work/pkg2zip -p1 -i ../../tools/patches/pkg2zip-npumdimg.patch
make -C .work/pkg2zip -j2 pkg2zip-npumdimg \
  CFLAGS='-std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -Wno-error=discarded-qualifiers -D_GNU_SOURCE -O2'
install -m 755 .work/pkg2zip/pkg2zip-npumdimg ~/.local/bin/pkg2zip-npumdimg
```

The compiler exception concerns an existing const qualifier warning in
`pkg2zip_sys.c`. Keep assertions enabled. Runtime discovery uses PATH or
`PKG2ZIP_NPUMDIMG`. Provenance includes the installed executable's SHA-256;
rebuilds changing that hash require an extractor revision bump.

Verified against the echochrome demo: the standalone decoder and unmodified
pkg2zip both produce 185,401,344 bytes with SHA-256
`affeb5cba3ddf43ae74db3d1e89c1651f927ee202519582d083dcd61838800a9`.
The ISO contains 752 files and 27 directories (independently checked with pycdlib).
PS1 payload formats are not handled by this decoder.

NPUMDIMG revision 1 recorded the initial standalone trial; revision 2 adds
probability-table bounds and widens block-count arithmetic. ISO revision 3,
PKG revision 4 and PBP revision 3 invalidate previous discovery results.
The patch is local, not submitted upstream.
