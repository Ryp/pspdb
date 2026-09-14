# Native Linux PSX extraction

PSPDB builds [PSXtract-2](https://github.com/has207/psxtract-2) as a native Linux
CLI. It receives the **whole PBP**, preserving single/multi-disc context, upstream
sector reconstruction, source-backed auxiliary files and decoded audio. It is
not the former DATA.BIN-only research entry point and does not invoke Wine,
Sony ACM, an external FFmpeg executable or another audio converter.

## Build

Requirements: Linux x86_64, Python 3.12+, Git, patch, GNU make, and a GCC-compatible
C/C++17 toolchain supporting x87 extended precision. No system FFmpeg development
package is required: the builder compiles a minimal static decoder from source.

Provide Git checkouts containing these exact commits:

- PSXtract-2: `4691fc405698d53927df6e4f59c3e9b113c13706`.
- [FFmpeg](https://github.com/FFmpeg/FFmpeg):
  `59dd21047e86badeb1b142dff03f18acbbd074fa`.

```sh
python3 tools/build_psxtract.py \
  --psxtract-source /path/to/psxtract-2 \
  --ffmpeg-source /path/to/FFmpeg \
  --output .work/pspdb-psxtract \
  --jobs 4
export PSPDB_PSXTRACT="$PWD/.work/pspdb-psxtract"
```

The builder archives the pinned commits rather than using modified checkout
files, uses `tools/prepare_native.py --exact` for the checked-in portability/audio
patches, embeds upstream CUE resources, and records source, patch, compiler and executable provenance beside
the output. Parser, audio, PGD and decompression boundary regressions run before
publication. Upstream GPLv3 and LGPL license notices are retained
beside the binary. No Sony DLL is required or redistributed.

The exact ATRAC3 path preserves the original numerical operation order and
float32 rounding boundaries using x87 extended intermediates. Stock FFmpeg or
an arbitrary compiler/architecture is not an equivalent replacement. The native
candidate reproduces the complete retained real audio-track oracle: 28,052,986
WAV bytes and 14,026,470 PCM samples, with zero differences. Independent transform,
QMF and gain comparisons—including 6,593 gain-boundary cases—cover the numerical
changes. This audio evidence is distinct from whole-container/multidisc coverage.

Whole-container differential checks also match all 39 Vib-Ribbon outputs
(including seven WAVs), all 22 two-disc Parasite Eve outputs, and all 16 Ginsei
outputs, including generated CUE line endings. These are bounded representative
checks, not a claim of universal title coverage or full-PKG admission without
required licenses.

## Run and ingest

Put `pspdb-psxtract` on PATH or set `PSPDB_PSXTRACT` to its absolute path. The old
`PSPDB_PSXTRACT2`, `PSPDB_WINE` and Wine-prefix configuration are not used.

For standalone extraction, invoke the native executable with one absolute
`EBOOT.PBP` path from a fresh output directory. Existing TEMP/output files are
refused rather than overwritten. Ambiguous embedded CUE choices require an
interactive terminal; unattended ambiguity fails. Decoder failures, including
audio failures, are not successful partial conversions. Failed standalone runs
can leave diagnostic files in their private output directory.
PBP headers and the complete section table are validated before section output;
copying uses one bounded buffer. Audio reads and authenticated PGD table/payload
ranges are checked before use. Auxiliary partitioning follows the released
executable's block-start scan rather than the undefined-overflow prefix search
in upstream source. Missing in-block terminators fail instead of reading beyond
decoded source bytes.

Ingestion runs that CLI in private scratch space. PBP parsing remains native
Zig-PSP; contextual POPS executable decryption remains a separate native operation.
PSX revision 2 attaches reconstructed output beneath the observed `DATA.BIN`
occurrence, and PBP revision 3 records the changed contextual provenance. Prior
revision records remain immutable. Provenance hashes the native executable;
there is no Wine executable hash.

The adapter inventories `disc.bin` (or numbered discs) and nonempty decoded
`ISO_HEADER.BIN`, numbered `ISO_HEADER_1.BIN` through `ISO_HEADER_5.BIN`,
`ISO_MAP.BIN`, `STARTDAT.BIN`, `SPECIAL_DATA.BIN`, `TRASH.BIN` and `OVERDUMP.BIN`.
Generated CUE files,
logs and intermediate files remain tool outputs, not catalog entries. A failed
supported descendant prevents successful parent publication. The CLI is still
file-based; this cutover does not claim in-memory PSX extraction.

## Evidence boundaries

Original PBP/section bytes remain distinct from reconstructed 2352-byte CD
sectors. Stored ATRAC3 payloads are not raw CD audio and cannot simply be appended
to a data-only image. Upstream reconstruction may repair sectors or synthesize
pregaps; successful decoding alone is not proof of original-media identity.

Only exact reference matches receive Redump associations. The existing reference
records are in `website/pspdb/data/redump-psx.json`; their applicability is based
on reconstructed byte identity and size, not title. Reconstructed CD BINs remain
leaves rather than a new filesystem/track inventory. Historical catalog counts
and scratch-store locations are not a claim about the current catalog.

Useful original inputs and old Windows oracle assets are retained separately
for differential checks. Do not indiscriminately remove shared `.work` or Wine
runtime directories while cleaning a build.
