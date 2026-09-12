# PSXtract DATA.BIN draft

Reuses Hykem's GPLv3 PSXtract from https://github.com/xdotnano/PSXtract,
pinned at `72618c6bc2c026e88e95d72700ec7d0238372d49`. No new disc decoder.
The C++ entry point calls upstream extraction directly on a single-disc
`PSISOIMG0000` payload; Zig-PSP remains responsible for unpacking PBP.

```sh
python tools/build_psxtract.py --psxtract-source .work/gaia-context/psxtract --output .work/psxtract-data
.work/psxtract-data path/to/DATA.BIN new-output-directory
```

The build archives the pinned commit, ignoring checkout modifications. Requires
Python, git, patch, a C compiler and a C++ compiler. Upstream source/license notices
remain in the build sources. The wrapper supplies Linux directory-call compatibility.
`tools/patches/psxtract-data.patch` propagates header/reconstruction errors and checks
block reads, compressed sizes and decoder return lengths. These are targeted checks,
not comprehensive malformed-input hardening. Use only as a research draft.

An existing output directory is refused. Failed runs can leave partial files;
none are automatically imported into the store or catalog. No `-c` conversion,
sector repair, generated CUE, or PBP extraction is performed. Multidisc input is
explicitly unsupported in this entry point.

## Decoder fix and validation (2026-09-12)

`tools/patches/psxtract-lz.patch` moves the output-full check to the shared loop
boundary. Upstream checks it only while decoding a literal. When a match fills
the output, it continues decoding trailing bits, then reports an invalid distance.
For GaiaSeed's first block, it has already produced all 37632 bytes before this
failure. This is a completion-check bug; no compression algorithm was rewritten.

The first hypothesis (a missing end-marker check) was rejected: PSP LZRC's
length-255 marker does not apply here; that length also occurs inside these PS1
blocks. A distance-65535 check likewise failed subsequent blocks. Neither
experimental change is in the final patch.

The build runs `test_lz.cpp`: a match exactly filling the buffer must succeed;
a match crossing the boundary must fail, with guard bytes preserved. The exact
boundary test fails on the original decoder.

All 6047 blocks across GaiaSeed, NPEE00044, NPHJ00032, NPJJ00024, NPJJ00469 and
NPUJ01342 now reconstruct with the expected output size and exit status zero.
Results/hashes: `.work/psxtract-fixed-results.json`. Outputs:
`.work/psxtract-complete-<sample>/`. Each contains an ISO9660 primary descriptor
at sector 16, in a 2352-byte Mode 2 sector. Temporary 2048-byte payload views were
listed with libarchive: five list without error. GaiaSeed's apparent truncation
is explained by its mixed-mode layout; see the coverage investigation below.
No complete-disc or Redump equivalence is claimed. Block-table checksums have
not been verified.

GaiaSeed's PGD header identifies `_SLPS_00624`; upstream also extracts STARTDAT,
SIMPLE imagery, and 28 stored audio payloads (TRACK_02–29). The original GaiaSeed
ISO.BIN is byte-identical to the corrected output: the prior claim that ignoring
this return error necessarily corrupted its bytes was too strong. Its SHA-256 is
`eb79cec78b1bc142b0d8798f79d71d4206d6a8051ed992925495fb760d164063`
(11101440 bytes).

Online alternatives checked before fixing:
- [PSXtract2021](https://github.com/Mr-Berzerk/PSXtract2021),
  `931b9feac78937cab07e478c8f79a4fa059b72f3`: Unix decoder identical.
- [psxtract-2](https://github.com/has207/psxtract-2),
  `4691fc405698d53927df6e4f59c3e9b113c13706`: essentially heap scratch allocation.
- [AKuHAK/psxtract](https://github.com/AKuHAK/psxtract),
  `ca4b9fe4ea1528613c3c786804d320db802c9553`: same relevant decoder behavior.

The native helper remains a research draft. Production ingest now uses PSXtract-2
as described below. Preserve stored audio bytes separately from subsequent conversion.

## GaiaSeed filesystem coverage investigation

The filesystem advertises 246288 sectors (the whole disc), while upstream ISO.BIN
contains 4720 sectors from 295 retained blocks. All 107 ordinary files and all
11 non-root directories are within that image. A research script independently
checked their extents; libarchive extracted every ordinary file with matching
sizes and SHA-256 hashes, including DUMMY.DMY. Evidence and per-file hashes:
`.work/gaia-disc-coverage.json`; reproduction: `.work/gaia-coverage.py`.

The other 28 file entries, `/CDDA/*.DA`, point to audio tracks. Every start LBA
exactly matches the corresponding track-table INDEX 01. All 28 separately emitted
TRACK_02.BIN through TRACK_29.BIN match the stored DATA.BIN extents byte-for-byte.
They are stored audio payloads, not raw 2352-byte CD sectors. psxtract-2 has an
existing unscramble/ATRAC3 conversion path; simply appending these files is wrong.

Libarchive reads the CDDA directory at LBA 4572, then tries to skip from 4573 to
the first audio track at 4873: 300 * 2048 = 614400 bytes. Only 147 sectors
(301056 bytes) remain in the data-only view, exactly explaining its error.
The prior conversational attribution to DUMMY.DMY was incorrect: that file is
entirely in bounds at LBA 629, size 763904.

The track table places track 2 INDEX 00 at LBA 4723 and INDEX 01 at 4873.
Upstream separates ten final marker-zero blocks as JUNK files; the first starts
at logical block position LBA 4720 and contains three sector-like records before
other data. No ordinary file depends on those blocks (last file ends at 4572,
last directory at 4573). Preserve these source-derived outputs rather than
silently discarding them or inventing replacement sectors.

One additional metadata anomaly: track 28's INDEX 00 contains `50 95 10`,
invalid BCD seconds. Its INDEX 01 still matches JAP_ED3.DA. Do not silently use
that INDEX 00 to generate a CUE without resolving it. Full-disc reconstruction
and audio fidelity remain separate from successful extraction of the stored data.

## PSXtract-2 full-disc validation

The official [PSXtract-2 v3.0 release](https://github.com/has207/psxtract-2/releases/tag/v3.0)
was run successfully on GaiaSeed using a workspace-local Wine 11.17 runtime.
Executable SHA-256:
`9c69146387c78a291f099f9c3e168a0d7d2910bed4d53f127b696302b0996f59`.
No system packages were installed. Runtime: `.work/wine-runtime/`; isolated prefix:
`.work/wine-psxtract2/`; release: `.work/psxtract2-release/psxtract-2/`.

From a fresh output directory, use absolute paths:

```sh
WINEPREFIX=/home/ryp/dev/pspdb/.work/wine-psxtract2 \
WINEDEBUG=-all WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=d' \
/home/ryp/dev/pspdb/.work/wine-runtime/usr/bin/wine \
/home/ryp/dev/pspdb/.work/psxtract2-release/psxtract-2/psxtract.exe \
/path/to/EBOOT.PBP
```

Unlike original PSXtract, this version converts by default; `-c` means cleanup.
It requires Wine IPC sockets, which the execution sandbox blocks; the test ran
with sandbox escalation. Its whole-PBP unpacker was used only for this upstream
validation; this does not replace Zig-PSP in production ingest.

Outputs in `.work/psxtract2-gaia/`:
`GaiaSeed - Project Seed Trap (Japan).bin` and corresponding `.cue`.
BIN: **579269376 bytes / 246288 sectors**, 29 tracks. All 28 audio track length
checks pass. Its bundled SLPS-00624 CUE supplies validated-format track timings
instead of relying solely on the malformed embedded INDEX00 field. All 107
ordinary files retain their verified sizes and hashes. The whole-disc payload
view now lists all 147 filesystem entries with libarchive, exit 0.
Report: `.work/psxtract2-validation.json`; log: `.work/psxtract2-gaia.log`.
BIN SHA-256: `bf9026f89c2230d4dfd67c3ba55c297068c814e561862bdea44bc8e122ddfcba`.

**Known upstream fidelity limitation:** upstream's data-track MD5 verification fails:
expected (bundled CUE) `18ee89c0cf38c642fbba699925b3f63a`, actual
`f1a34dc8e00cd682621f4295f3fba2ba`. No original matching disc was available to
localize that discrepancy. Matching the 107 files does not prove sector-level
identity. Audio was decoded from lossy ATRAC3 and cannot be claimed bit-identical
to original CD audio. This solves complete layout/audio reconstruction, not a
Redump-identical restoration. No emulator/hardware play test was performed.

Production ingest uses PSXtract-2 as the full-disc conversion backend. Retain authentic stored payloads and distinguish its generated CUE,
repaired sectors and decoded audio from source inventory. The standalone native
PSXtract draft remains useful for direct DATA.BIN source-preserving extraction.


### Upstream confirms GaiaSeed's expected hash mismatch

[Issue #3](https://github.com/has207/psxtract-2/issues/3), opened by maintainer
has207, explicitly lists Gaia Seed among games missing an ECC signature/watermark
in otherwise unused final disc sectors. The maintainer later
[clarifies this is cosmetic](https://github.com/has207/psxtract-2/issues/3#issuecomment-2076407833),
and distinguishes it from actual audio/subheader problems. The expected effect
is a Redump checksum mismatch despite playable extraction.

Treat our GaiaSeed mismatch as consistent with this documented upstream
limitation, not an extraction failure or integration blocker. We have not
compared against original disc bytes to prove the exact differing offsets;
retain the recorded hashes and known-limitation status. This data-track issue
is separate from unavoidable audio differences caused by lossy ATRAC3.
Local tracker snapshots: `.work/psxtract2-issues.json` and
`.work/psxtract2-issue3-comments.json`.

## First verified PSN → Redump match

[Saikyou Ginsei Chess (Japan), Redump #38300](http://redump.org/disc/38300/)
was the first additional PSXtract-2 conversion tried after GaiaSeed. Already
available package NPJJ-00469 reconstructs the original SLPS-03482 single-track
CD image: 38671584 bytes, CRC32 `26d0aa26`, MD5
`a42c72d7fb1fb14f6c39bf0e3dfac200`, SHA-1
`17949ba0b7d55e6cb2da70c98a926a5df47e3a67`. All four fields were compared directly
against Redump's page, not solely the bundled CUE. Structured provenance and
source hashes are in [the packaged reference data](../../website/pspdb/data/redump-psx.json).

The package is imported into the main versioned catalog. The reconstructed BIN
is retained as SHA-256 `1f402cf36199f458e6da9c9ae908576332b0e48b29889abf2b182077e9fb803c`
in the content store; the website now annotates matching disc entries with Redump links. The match applies to PSXtract-2's reconstructed/repaired
2352-byte CD sectors, not the compressed PSISOIMG payload or PSP UMD format.


## Integrated ingest (current)

PBP v9 calls both contextual helpers: POPS decrypts DATA.PSP, PSXtract-2 converts
the disc content. Both receive the entire parent PBP and attach their results to
the correct section occurrence. DATA.BIN has an identity-named inline extraction
with `disc.bin` plus nonempty decoded auxiliary containers. No generated CUE or
JSON report is inventoried. The reconstructed 2352-byte BIN is a leaf for now;
its internal ISO9660/audio filesystem is not recursively cataloged. Original
PBP/DATA.BIN bytes remain in the store. PSXtract-2's internal PBP unpacker is
only part of that subprocess; Zig-PSP still produces the source section inventory.

PSX extractor revision1 records the executable and Wine executable hashes.
Catalog status checks both contextual helper provenances; failure to reconstruct
prevents successful parent publication. SFO parsing still uses Zig-PSP. PKG v5
normalizes the observed CP1252 trademark byte in otherwise ASCII titles to UTF8
for metadata only; other malformed text remains rejected.

Override dependencies with `PSPDB_PSXTRACT2`, `PSPDB_WINE`, `WINEPREFIX`.
Defaults use PATH (`psxtract.exe`, `wine`) and `~/.cache/pspdb/wine-psxtract2`.
On praetor, ~/.local/bin links resolve to the verified workspace release/runtime,
and the cache prefix link resolves to `.work/wine-psxtract2`. Keep those assets
when cleaning `.work`. Wine execution needs its local IPC sockets permitted.

Seven on-disk PSX packages now ingested: GaiaSeed, Saikyou Ginsei Chess,
Cotton Original, Arcade Hits Raiden, Crossroad Crisis, Vib-Ribbon, Mega Man
Legends (user's ~/download package, TSV SHA256 verified). Evidence:
`.work/psx-ingest-results.json`, `.work/ingest-psx-all-final.log` and
`.work/psx-final-skip.log`. All seven current roots/inline disc trees are exposed
by the live website. 142 reachable objects (2197841998 bytes) verified locally
and synchronized to NAS. Catalog validation:1306 pairs,47 existing UMD ISOs.

### Website Redump annotations

Four reconstructed single-track discs now have exact references: Saikyou Ginsei
Chess (#38300), Cotton Original SuperLite (#10679), Arcade Hits Raiden (#17952),
and Crossroad Crisis (#16362). Size, CRC32, MD5 and SHA1 were independently checked
against each Redump page; runtime association uses recorded SHA256 plus size.
Canonical provenance data is `website/pspdb/data/redump-psx.json` (moved from the
previous tools/psxtract/redump-matches.json research file). It is packaged with
the website and applied to nested entries in live API and static exports. Known
nonmatching/multitrack images do not receive an exact-match link.
