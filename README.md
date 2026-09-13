# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extractor kind
and source hash owns revisioned inventories; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/PKG/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. `catalog/` contains versioned metadata and inventories contributed through PRs.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.16.0**, **libarchive** development headers/library, and GNU **patch**.
The first build fetches pinned Zig-PSP, pspdecrypt and make-npdata dependencies.

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog
```

Pass multiple input folders as positional arguments to ingest them together:

```sh
./ingest/zig-out/bin/pspdb-ingest /path/to/umd-videos /path/to/umd-games /path/to/pkgs \
  --catalog catalog --threads 2
```

All folders share one worker pool, thread cap, catalog/store configuration, and
combined summary. A failed folder does not stop the others; any failure makes
the command exit nonzero. Overlapping folders are scanned as supplied, without
deduplicating their paths.

Discovers ISO and PKG files, including members of ZIP archives. ISOs require a
root `UMD_DATA.BIN`. Retail PSP/PS1 PKGs are decrypted by the native PKG extractor,
preserving every file and directory at its original path. `--store` is optional. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips current
ISO/PKG results when `--catalog` is set; it is **off by default**. Bump the affected extractor revision when extraction behavior changes.

Filesystem discovery stays parallel. ISO/PKG intake concurrency is `max(1, N / 4)`,
rounded down from the configured `--threads N` cap before reserving a progress thread.
This covers hashing, metadata parsing, and the immediate file walk, including ZIP members.
Nested extractors share the worker pool, retain their input bytes in memory, and
take scheduling priority over new intakes.

Each extractor revision owns a namespace under `catalog/<extractor>/v<version>/`.
For example, ISO extractor revision 1 writes two adjacent files:

```text
catalog/iso/v1/<source-sha256>-ingest.json
catalog/iso/v1/<source-sha256>-tree.json
```

The ingest record contains source metadata; the tree contains the immediate
output inventory and tool provenance. See the [metadata schema](schemas/record.schema.json)
and [tree schema](schemas/tree.schema.json). The tree is published before its
ingest record. Results are immutable within a revision; different results in the
same namespace raise `CatalogConflict`. New revisions preserve previous results.
The same bytes may have separate source roles: an original `iso` observation and
a nested `iso9660` extraction retain independent inventories and provenance.
Their SHA-256/size byte identity and stored object remain shared.
Inputs are read-only. Catalog JSON is tracked in Git; object stores and source
images stay local. See [CONTRIBUTING.md](CONTRIBUTING.md) to submit ingested content
and validate new metadata/tree pairs.

SFO metadata is parsed in memory with the pinned Zig-PSP zSFOTool code. A
[dependency patch](tools/patches/zig-psp-sfo-memory.md) exposes its reader and
adds bounds validation; PSPDB only selects and validates its catalog fields.

Metadata is read independently before file inventory/storage: `UMD_DATA.BIN`
and both game/video `PARAM.SFO` paths. When both SFOs exist, game metadata takes
precedence. If neither exists, the updater SFO supplies the title and version; its generic
ID does not replace the disc identifier.

ISO and nested ISO9660 extraction resolve shared-extent file aliases
by exact path, preserving distinct case-sensitive filenames. Metadata lookup
remains case-insensitive; it must not determine which bytes an inventory path owns.

PKGs write their own versioned pairs under `catalog/pkg/v2/`. Package metadata
includes content ID, title ID, content type, raw metadata-entry-3 `package_flags`
(when present), and available PSP title/version/firmware fields. Whole-package
SHA-256/SHA-1 identify the unchanged input. The website and static export retain
the **psp** root row: its size column sums original ISO/PKG sizes without counting
expanded contents again. Packages appear under **psn**, alongside **umd**.

Generic PSP packages (content types 7, 14) appear directly under **psn**.
The current update heuristic puts content type 7 with `package_flags & 0x10`
under **psn/update**. This bit separates all 67 verified updates from 30 non-update
controls in the observed corpus; it is an empirical heuristic, not a formal
format guarantee. Legacy type-7 records without flags remain directly under
**psn** until re-ingested. Other content types do not use the update heuristic.
Other types select **minis** (15), **psone_classic** (6), **neogeo** (16), or
**theme** (9, within supported PSP packages). Missing or unrecognized types fall under **unknown**; empty groups
are omitted. Grouping preserves package labels and extracted paths and
requires no ingestion options.
Embedded PBP files use the nested extraction pipeline whenever a catalog is set;
the content store is optional and only persists extracted bytes.
Package title metadata is taken from the already-decrypted EBOOT.PBP during its
inventory walk, without decrypting the full game payload again. Inner PBP metadata
retains precedence over outer package metadata regardless of entry order.
The PKG extractor supports retail PSP and PS1 packages, including standard PSP
theme packages (content type 9), not debug, native PS3, or Vita packages.
Themes may legitimately omit `PARAM.SFO`; no title metadata is invented. Present
malformed metadata still fails. Theme payloads retain their original bytes and
paths, including opaque PSPEDAT wrappers. Package decryption does not imply that every inner DRM payload is
supported: as with ISOs, a nested extractor failure fails that source's full ingest.

## PSN reference inventory and bounded acquisition

Fetch the current PSP/PSX NoPayStation TSV snapshots, inventory them, and import
their inline RAPs (no PKG downloads):

```sh
uv run --locked python tools/psn_acquire.py \
  --work .work/psn-acquire --catalog catalog
```

With no positional paths, each run fetches all six supported lists from
`https://nopaystation.com/tsv/` over HTTPS: PSP games, demos, DLCs, themes, updates,
and PSX games. Validated snapshots are cached under `--work/snapshots`, with private
permissions because TSVs may contain RAPs. The report records source URLs and
snapshot hashes. Fetches use `--timeout`, reject redirects, and cap each response
at 16 MiB. A failed or malformed response aborts without replacing the cache;
there is no silent fallback to stale data.

Pass local TSV files or directories to skip fetching. This also allows explicitly
reusing the cached snapshots offline:

```sh
uv run --locked python tools/psn_acquire.py .work/psn-acquire/snapshots \
  --work .work/psn-acquire --catalog catalog
```

`--limit` controls PKG attempts only, not TSV fetching; `--category` filters PKG
downloads without narrowing the fetched lists or RAP import.

The machine-local `report.json` accounts for every row across unique snapshots,
retains duplicate-source attribution and conflicting references, and excludes
license columns. Counts describe reference/package candidates, not a complete
enumeration of PSN. Missing hashes or sizes remain unknown.

Acquisition imports valid inline `RAP` hex into private, exactly 16-byte
`<Content ID>.rap` files, including on inventory-only runs (`--limit 0`) and for
packages already downloaded or ingested. Download filters do not restrict license
import. Acquisition and EDAT extraction share `PSPDB_RAP_DIR`, defaulting to
`${XDG_DATA_HOME:-$HOME/.local/share}/pspdb/licenses`. Acquisition's `--rap-dir`
overrides that location for the import only; use the same `PSPDB_RAP_DIR` when
ingesting. Unset an old `PSPDB_RAP_DIR` override to use the shared default.

New license directories are mode 0700 and new files are mode 0600. Imports are
atomic and never overwrite existing keys; identical keys are reused. Conflicting
snapshot keys, conflicts with stored keys, malformed keys and unsafe files are
reported rather than silently replaced. `report.json` includes license content IDs
and `imported`, `present`, `missing`, `invalid`, or `conflict` statuses; stdout
includes their counts and the store directory. Neither includes key bytes or
license download URLs. No license URLs are fetched. A blank or `NOT REQUIRED` RAP
field supplies no key; `missing` reports availability, not whether that package
needs EDAT decryption. Supply a valid local RAP/updated snapshot for missing keys;
resolve conflicting or invalid files explicitly before retrying.

Download a bounded batch from listed public Sony package URLs, then ingest separately:

```sh
uv run --locked python tools/psn_acquire.py \
  --work .work/psn-acquire --catalog catalog --category PSP_DLCS --limit 5
./ingest/zig-out/bin/pspdb-ingest .work/psn-acquire/completed \
  --catalog .work/psn-catalog --store /path/to/store
```

Acquisition is sequential, uses finite retries/timeouts, preserves 2 GiB free by
default, and publishes completed `.pkg` files only after PKG-header and supplied
size/hash checks. Missing reference hashes never become hash-confirmed.
Interrupted transfers resume only with a strong remote ETag and a matching saved
local prefix; otherwise they restart. Repeated runs reuse verified files.
Use `--package` with a report candidate ID for exact selection, `--reuse` for
existing local packages, and `--retry-failed` to revisit permanent failures.
Supported sources are `zeus.dl.playstation.net/cdn/` and the update host
`b0.ww.np.dl.playstation.net/tppkg/np/`. Host-specific paths, public DNS targets,
and credential-free URLs are enforced. Other hosts and redirects remain
explicitly unhandled rather than followed.

Re-run inventory against the resulting catalog to distinguish exact ingested
hash/size matches from downloaded packages. Catalog matching does not establish
extractor freshness or support for every inner format. Keep extraction failures
as separate ingest evidence; a successful download is not a successful ingest.
Review and validate staged catalog pairs before contributing them.

## Extractor revisions and regeneration

[tools/extractor_versions.json](tools/extractor_versions.json) is the shared revision
registry for native and external extractors. Revisions are positive integer strings; folder names add a `v` prefix (`v1`, `v2`, etc.).
To change the ISO extractor, increment `iso` (for example, `"1"` to `"2"`) and rebuild:

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
uv run --locked python tools/catalog_status.py --catalog catalog
# Add --json for per-source provenance and affected ISO hashes.
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store --skip-existing
```

The status command is read-only. It compares revisions, executable SHA-256 hashes,
and extraction options (including the RCOMage INI digest), and follows child hashes
to report affected ISO and PKG roots. Missing tools are reported as unavailable, never current.
If a tool/configuration changes within the same revision, bump that extractor's
revision before regenerating; existing results will not be overwritten.
Changes to adapter behavior, naming rules, metadata parsing, or file detection also
require a revision bump for the extractor whose output changes. `schema_version`
remains the JSON format version, independent of extractor revisions.

`--skip-existing` uses uv/Python for the read-only provenance scan at startup.
Affected ISOs are read again, while current intermediate
extractions reuse verified stored child bytes. Missing stored children cause that
extractor to run again. Source ISOs/ZIPs must still be available; this command does
not regenerate arbitrary sources directly from the object store. Without
`--skip-existing`, all encountered sources are processed as before.
Intermediate freshness is scoped by extractor kind and source hash:
`fresh_trees[kind][sha256]` in status JSON. A fresh original ISO observation does
not authorize reuse of a stale ISO9660 extraction of the same bytes.

The website/export selects the highest numeric **complete** revision per extractor
kind and source hash, so old revisions do not create duplicate browser rows. An incomplete newer
pair does not hide an older complete result. Legacy `catalog/<extractor>/<hash>.json`
and `catalog/trees/<hash>.json` remain readable, but the status command reports
them as unversioned; regeneration writes versioned pairs and leaves them intact.

Extracted containers show subdued, right-aligned kind and version tags, such as
`PBP` and `v12`. Outdated version tags use a muted amber tint and a tooltip such
as `Outdated PBP subtree v11 (latest is v12)`. Existing contents remain browsable.
Warnings describe that container's own extraction, not the freshness of its
descendants. Current, newer, and unknown revisions are not marked.
The local viewer reads `tools/extractor_versions.json` from its source checkout
on each catalog request; without that registry, it makes no freshness claim.
Static exports capture the comparison at export time and must be regenerated
after a registry change.

## Browse

Requires **uv** and **Python 3.11+**. The website has no third-party runtime dependencies.

```sh
uv run pspdb-web --catalog catalog --host 0.0.0.0 --port 8000 --store /path/to/store
```

Open **http://localhost:8000**, or the host's LAN address. Omit `--store` to hide
downloads; omit `--host` to bind only to localhost. Add `--redump /path/to/dat.zip`
(or an XML DAT) to link exact ISO SHA-1 + size matches to Redump. The DAT is
loaded at startup; ingest records hashes without depending on Redump.
Add `--umdatabase /path/to/pages` for exact SHA-1 links from saved UMDatabase
entry pages named `ID.html` (for example, `E39CFE68.html`).
UMD video labels use the SFO title when available, otherwise the observed disc
identifier. Missing optional SFO metadata does not prevent browsing its inventory.
The API and exported `catalog.json` keep inventories in `trees[kind][sha256]`.
Root rows use their explicit `iso` or `pkg` inventory; nested files use their
derived extractor inventory. Inline contextual extractions retain occurrence precedence.

## Static hosting / GitHub Pages

```sh
uv run --locked pspdb-web export --catalog catalog --output dist/site
uv run --locked python -m http.server --directory dist 8001
```

Open `http://localhost:8001/site/`. The output directory must be empty. Export
accepts the same `--redump` and `--umdatabase` sources and embeds their matches.
It contains only the browser assets and metadata; Store/downloads are disabled.
Relative asset URLs support repository paths such as `/pspdb/`.

Keep source code on `main` and exported snapshots at the root of a separate
`pages` branch (`index.html`, assets, and `catalog.json`, without a `site/` wrapper).
Export into an empty staging directory, then copy its contents into that branch.
Pages can publish directly from **pages / (root)**, or use **GitHub Actions** and
the manual **Deploy GitHub Pages snapshot** workflow on `main`. Neither approach
needs access to source images or ingestion in Actions. Refresh the snapshot with a new export
and commit on `pages`; rerun the manual workflow if using Actions as the source.
A private repository requires a Pages-capable paid
GitHub plan; the exported site is normally public.

## Check

Validate the tracked catalog without source images or external extractors:

```sh
uv run --locked python tools/validate_catalog.py
```

The ingest CLI tests build the current executable and generate their own ISO/PKG/ZIP
fixtures. PKG fixtures use OpenSSL for independent AES encryption.

```sh
(cd ingest && zig build test)
uv sync --locked
uv run --locked python -m unittest discover -s ingest/tests
uv run --locked python -m unittest discover -s website/tests
uv run --locked python -m unittest discover -s tools/tests
node website/tests/tree-catalog.mjs
```

## Extractors

PSAR, NPUMDIMG, nested ISO9660, RCO, PRX/~PSP, SCE, PBP, gzip, KL3E, KL4E, VMP,
supported NPD EDAT and legacy DOCUMENT processing runs automatically during ISO/PKG/ZIP ingest
when a catalog is set, with or without a content store:

```sh
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog
```

PSMF/PMF movies and raw MPEG program streams remain opaque source files; no movie subtrees are generated.

Detection uses signatures, independent of filenames. SCE borrows slices directly.
PBP extraction and embedded PKG metadata use Zig-PSP’s PBP reader in memory, with
borrowed slices and no temporary files. The pinned dependency receives a
[patch exposing its memory API and fixing bounds/final-section handling](tools/patches/zig-psp-pbp-memory.md). Remaining external tools receive input bytes in private temporary
directories, not by reopening CAS objects. Zig hashes their outputs and queues
nested extraction using retained buffers; `--store` additionally persists those bytes.
Temporary input/output directories are removed after the immediate walk.
Paired manuals retain their exact input and companion views until contextual extraction.
An ISO is reported complete only after all its extraction jobs succeed.

The Zig inventory model lives in `ingest/src/inventory.zig`: source results,
entries, contextual dependencies, serialization and owned-data cleanup.
`processor.zig` performs extraction/inventory work; `catalog.zig` publishes that
model without depending on the processor. Scheduling remains in `ingest.zig`.
`gzip.zig` owns complete-stream and bounded single-member decompression;
`containers.zig` only exposes borrowed container slices. PRX calls the codecs
directly, keeping its declared-size and authentication boundaries explicit.

Install `pspdecrypt` for PSAR and the patched `rcomage` on PATH (overrides:
`PSPDECRYPT`, `RCOMAGE`). RCOMage loads INI files from `../share/rcomage` relative to its binary
(override: `RCOMAGE_DATA`). The Linux/LZR patch is in
`tools/patches/rcomage-lzr-linux.patch`.
Python adapters run through uv and are embedded in the ingest binary.

PSAR revision 2 requires rebuilding the pinned external decrypter below for the
shared PRX recipes, exact decoded firmware-table lengths, and complete CBC/IPL
input bounds. Unpatched builds can retain binary tail bytes in decoded tables.
Building requires Git, Make, a C/C++ compiler, zlib and OpenSSL development headers:

```sh
uv run --locked python tools/build_pspdecrypt.py \
  --pspdecrypt-source /path/to/pspdecrypt \
  --output .work/pspdecrypt
export PSPDECRYPT="$PWD/.work/pspdecrypt"
```

The source checkout must contain commit
`c156627db7634d395c380c0a9589130f603307fc`; local modifications are not used or
changed. Nothing is installed globally. The patch reuses the
[published type-5 XOR recipe](https://github.com/hrydgard/ppsspp/blob/35d69dd4a11632ab6633b2fada84d393541e6131/Core/ELF/PrxDecrypter.cpp#L477),
preserving the decoder's header and ciphertext integrity checks. It requires no
title-specific key or sibling PBP section. PSAR extraction writes exactly the
table decoder's returned length and rejects invalid lengths before allocation
or publication. Decoded package tables describe model selection, not a complete
installed firmware filesystem.

PRX and KL3E/KL4E decode in memory through a pinned, patched pspdecrypt library
linked by the Zig build. They need no external helper, NAS input reread, or
temporary output files. This links GPLv3 pspdecrypt code into the ingest binary.
PRX supports `~PSP` modules and `PSPsysGP` firmware resources, with 183 tag values
and layouts 0/1/2/4/5/6/9; legacy layout 8 shares the layout-0 algorithm. Coverage
includes standard update XOR recipes and firmware index keys, including 2.50.
Mutable KIRK state is thread-local. This is not full authentication: type-6 and
type-9 external ECDSA signatures are not verified, and type fallback can accept
damaged ciphertext.

Generic layouts 3/7/10 and runtime-key-dependent PAUTH/NPDRM modules are not
supported by the standalone PRX path. PAUTH needs the game's runtime work area;
NPDRM can require a per-module key. Fixed XOR constants do not replace those keys.
Supported POPS executables use the native contextual decoder with their DATA.BIN sibling.

PRX revision 4 decrypts and expands contained gzip/KL/2RLZ data in one extraction,
publishing the final `module.elf` or `payload.bin` directly. The original PRX
remains stored; decrypted compressed intermediates are neither stored nor
cataloged. Revision-1 external and revision-2 native intermediate trees remain
historical records. Standalone KL extractors remain at revision 2.
Native PRX, KL and EDAT decoders use `pspdb-ingest` provenance; contextual POPS uses `pspdb-pops`.

The bounded Zig 2RLZ decoder is adapted from BenHur's libLZR 0.11, licensed
[CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/), not GPLv3.
Its attribution and share-alike requirements remain applicable; redistribution
of the combined binary requires resolving compatibility with the linked GPLv3 code.

When a `~PSP` module's compression flag is set, `elf_size` supplies the exact expanded
allocation size, bounded to 64 MiB and checked against the decoder's result.
Unflagged modules and `PSPsysGP` resources can contain compressed streams whose
expanded size is not declared by that field; those use bounded decoding up to 64 MiB.
The [reconstructed firmware reboot caller](https://github.com/uofw/uofw/blob/master/src/kd/loadexec/loadexec.c#L1691-L1695)
similarly supplies a fixed destination capacity, not an exact output length.
Uncompressed payloads retain their full KIRK-declared length, including any bytes
beyond `elf_size`. PRX-contained gzip validates one member's CRC32/ISIZE; bytes
after that member belong to the envelope.

Standalone gzip decoding uses Zig's standard-library DEFLATE decoder on the retained
input buffer, without a Python process, NAS input reread, or temporary output
files. Each member's CRC32 and decoded size are checked before any output is
published; concatenated members and zero padding retain Python gzip behavior.
The single decoded child is named `module.elf`, `payload.gz`, or `payload.bin`
according to its signature, then enters normal storage and recursive extraction.
Standalone KL3E/KL4E streams similarly retain their compressed bytes and get a decoded child.
ELF files containing bounded `~PSP` wrappers expose them as `embedded-<offset>.psp`
children, which recurse through the same decryption pipeline.
Executable children inherit their source basename for display and download.
PRX revision 4 exposes decoded ELF directly with `.elf`; historical trees can
retain intermediate suffixes such as `.prx.gz` or `.prx.kl4e`.
Shared inventories retain canonical paths, so identical content can appear
under different filenames without conflicting catalog records.
RCO outputs include native resources and generated XML; provenance includes the
binary hash and configuration digest. Child failures fail their ISO's ingest.
`--skip-existing` skips an ISO only when its result and known reachable extraction
results are current. Current intermediate trees can be reused from the object store
while outdated descendants are extracted again. The thread
cap applies to ingest itself; external tools run in child processes.

KL decoding bounds both input and output, rejects malformed or truncated streams,
and caps decoded output at 64 MiB. Only output-capacity exhaustion retries with
a larger buffer. `pspdecrypt-kle` and `PSPDECRYPT_KLE` are no longer used by ingest.

NPUMDIMG (`DATA.BIN`, PBP section 7) decodes in memory through the pinned
[pkg2zip AES/LZRC backend](tools/patches/pkg2zip-npumdimg.md). No separate
`pkg2zip-npumdimg` installation or `PKG2ZIP_NPUMDIMG` override is needed.
Ingest retains `DATA.BIN`, attaches the exact owned `disc.iso` beneath it, and
inventories that ISO under `iso9660`. Executable files recurse normally.
Derived ISOs stay beneath their PSN package rather than becoming UMD roots;
successful decoding and the ISO sanity check do not establish authenticity.
This disc decoder handles NPUMDIMG, not PS1 disc payloads or EDAT. PS1 executable
decryption uses the native contextual decoder; PS1 disc reconstruction still
uses the whole-PBP external path described below.

NPD EDAT files are authenticated and decrypted in memory by the native ingester.
The Zig build links pinned make-npdata commit
`5f44642fa24331da79f4bae6bea516f1784cf1c5`, with private-buffer and thread-safe
AES-table patches. Its GPLv3 crypto code is linked into the executable.
No EDAT subprocess, input reread, temporary plaintext file or `PSPDB_EDAT` helper is used.

The key boundary selects a regular, nonsymlink, exactly 16-byte
`<NPD-content-id>.rap` from the shared license directory described above.
Override that directory with `PSPDB_RAP_DIR`; otherwise `XDG_DATA_HOME` or
`~/.local/share/pspdb/licenses` supplies the default. License bytes never enter
catalog JSON or provenance. Missing/invalid licenses and failed authentication
fail the ingest root. EDAT revision 2 records native `pspdb-ingest` provenance;
ISO/PKG revision 2 enables complete recursive inventories without a store.

EDAT extraction supports license-2 NPD v1/flags-0 and v2/flags-0-or-0x0c files,
with 16 KiB blocks and at most 64 MiB plaintext. Keyed header, metadata-table and
every ciphertext-block MAC must pass before publication. The original EDAT,
including signatures and any optional 16-byte footer, stays unchanged; the decoder
does not verify filename-dependent hashes or ECDSA signatures. Its sole child is
`payload.DAT`, displayed and downloaded using the EDAT source stem:
`ISO.BIN.EDAT` yields `ISO.BIN.DAT`, and `MINIS.EDAT` yields `MINIS.DAT`.
Recognized payload formats still recurse through their registered extractors.

Big-endian NPUMDIMG metadata does not contain an identified filesystem.
It remains a single DAT file for inspection or a future extractor, rather than
being split into synthetic header fields and block records. It is not sent to
the little-endian NPUMDIMG disc decoder. International Snooker (EU) exercises
both payload sizes: 80-byte `MINIS.DAT` and 116,704-byte `ISO.BIN.DAT`.
Original EDAT and decrypted DAT bytes are retained unchanged.

For NPUMDIMG PBPs, the Zig [DATA.PSP parser](tools/patches/data-psp.md) verifies the
SFO/content-ID signature using OpenSSL libcrypto. Generated verification reports
are not included in the extracted file inventory.
Install OpenSSL development headers/library when building ingest. Optional
STARTDAT and OPNSSMP containers are exposed without decoding their contents.

Supported PS1 POPS executables decode in memory through the linked
[POPS decoder](tools/pops/README.md), without a helper installation or `PSPDB_POPS`.
It recovers the title key from the borrowed DATA.BIN sibling, while the catalog
attaches decoded output specifically beneath `DATA.PSP`. The file hash and
download remain those of the original section. This contextual subtree uses
native `pspdb-pops` revision-2 provenance and normal decoded-file hashes; it does
not create a global standalone PRX result or a generated report.
Decoded ELF payloads use `.elf`, including PSP PRX modules. Gzip and KL3E/KL4E
trees use `decoded_suffix` to retain that format in display and download names,
without duplicating existing `.elf` suffixes.

PSN package labels use `XXXX-12345 Title`, with the serial styled like UMD IDs; collisions receive a short SHA-256
suffix that expands as needed. Full content IDs remain searchable. Hash-based
catalog identity and links remain stable when a display title changes.


PS1 PKG ingest uses Zig-PSP for PBP/SFO parsing and PSXtract-2 under Wine for
full disc reconstruction, attached beneath the original `DATA.BIN` section.
Configure `PSPDB_PSXTRACT2`, `PSPDB_WINE`, and optionally `WINEPREFIX`, or put
`psxtract.exe` and `wine` on PATH. See [PS1 extraction setup and validation](tools/psxtract/README.md).

Standard VMP memory-card wrappers expose their unchanged 131072-byte raw card as
an `.mcr` child. This follows the
[upstream wrapper layout](https://github.com/sahlberg/pop-fe/blob/d74e4ab44eedbf41abd759a8db7cd091779dea82/vmp.py):
131200 total bytes, `00 50 4d 56` magic and a 128-byte header. This is byte
extraction, not signature verification or per-save filesystem interpretation.
VMP extraction preserves the original wrapper.

### Legacy DOCUMENT manuals

Fixed-key PS1/PSP manuals and explicitly paired PSP manuals use the pinned
[PSP-DOCUMENT.DAT reader](https://github.com/seiya-dev/PSP-DOCUMENT.DAT/tree/8c95b37949c9a9ca183b7fd69c85d2e2dad7216d).
Build its isolated helper with Python 3.12+; dependencies stay in the uv environment:

```sh
uv sync --locked
git clone https://github.com/seiya-dev/PSP-DOCUMENT.DAT .work/PSP-DOCUMENT.DAT
git -C .work/PSP-DOCUMENT.DAT checkout 8c95b37949c9a9ca183b7fd69c85d2e2dad7216d
uv run --locked python tools/build_document.py \
  --source .work/PSP-DOCUMENT.DAT --output .work/pspdb-document
PSPDB_DOCUMENT="$PWD/.work/pspdb-document" uv run --locked \
  ./ingest/zig-out/bin/pspdb-ingest /path/to/inputs \
  --catalog catalog --store /path/to/store
```

The builder verifies pinned source hashes, applies bounded-reader safety changes,
and creates a deterministic zipapp without modifying upstream sources or installing
system packages. Keep `PSPDB_DOCUMENT` set for freshness scans too, and run through
`uv run --locked` so the helper has its declared Pillow/PyCryptodome dependencies.

Fixed-key recognition uses the encrypted DOC magic/version block, not filenames
or generic PGD magic. The reader checks supported header/table/page protection;
these are source-consistency checks, not independent trusted-origin authentication.
Extraction preserves the wrapper and exact PNG bytes. Neutral `psp/001.png` and
`ps3/001.png` paths retain each platform's page ordinals, including shared frames.
The helper emits a JSON source/page map on stdout, including original source
identity and frame offsets/sizes/hashes. This generated metadata is not an
extracted file; the output directory and DOCUMENT inventory contain only page PNGs.

All expected pages must pass PNG CRC, end-boundary and pixel decoding checks before
atomic publication. Late-page failure leaves the caller's output empty and fails
its ingest root. No whole-disc reconstruction or inferred PBP key is used.
Support is limited to the exercised 99-slot families with PS3 frames referencing
PSP frames. Generic PGD, 999-slot tables and unique PS3-only frames remain unsupported.
Resource limits are 64 MiB input, 256 MiB total page frames, 4096 encrypted-range
descriptors per page and 16 Mi pixels per image.

For non-default PSP manuals, PKG, ISO and nested ISO9660 inventories bind an
unrecognized legacy-PGD `DOCUMENT.DAT` to its exact same-directory `DOCINFO.EDAT`.
The companion must match the exercised 304-byte/eight-byte-key layout and pass
outer signature, inner header, MAC-table and complete ciphertext-block checks,
including padding. Unsupported or damaged present companions fail the root;
without a companion the unrecognized wrapper remains opaque. The 320-byte
companion variant and other generic PSPEDAT/PGD extraction remain unsupported;
the separate NPD EDAT extractor above does not handle those wrappers.

Paired results are inline on the original DOCUMENT occurrence, never globally
cached by its hash alone. `dependencies` records the companion's path relative to
that immediate inventory, SHA-256 and size. Reuse validates the same sibling
binding; helper provenance changes invalidate the containing result. Generated
page maps also retain the companion's byte identity. Titles are not key inputs.
Direct helper use requires an explicit `--docinfo PATH`; it never discovers
siblings from the input filename.

DOCUMENT extraction publishes only page images, with the generated source/page
map on helper stdout instead of a `structure.json` child. This also applies to
inline manual inventories. Rebuild the DOCUMENT helper before use.

