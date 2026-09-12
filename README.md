# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extracted source hash owns its
inventory; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/PKG/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. `catalog/` contains versioned metadata and inventories contributed through PRs.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.16.0**, **libarchive** development headers/library, and GNU **patch**.
The first build fetches the pinned Zig-PSP dependency.

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store
```

Discovers ISO and PKG files, including members of ZIP archives. ISOs require a
root `UMD_DATA.BIN`. Retail PSP/PS1 PKGs are decrypted by the native PKG extractor,
preserving every file and directory at its original path. `--store` is optional. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips current
ISO/PKG results when `--catalog` is set; it is **off by default**. Bump the affected extractor revision when extraction behavior changes.

Filesystem discovery stays parallel, but only one ISO or PKG is admitted through hashing,
metadata parsing, and its immediate file walk at a time. Nested extractors share
the worker pool and retain their input bytes in memory; they can overlap the next ISO.

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
Inputs are read-only. Catalog JSON is tracked in Git; object stores and source
images stay local. See [CONTRIBUTING.md](CONTRIBUTING.md) to submit ingested content
and validate new metadata/tree pairs.

SFO metadata is parsed in memory with the pinned Zig-PSP zSFOTool code. A
[dependency patch](tools/patches/zig-psp-sfo-memory.md) exposes its reader and
adds bounds validation; PSPDB only selects and validates its catalog fields.
The reader change is recorded in ISO revision 2 and PKG revision 3.

Metadata is read independently before file inventory/storage: `UMD_DATA.BIN`
and both game/video `PARAM.SFO` paths. When both SFOs exist, game metadata takes
precedence. If neither exists, the updater SFO supplies the title and version; its generic
ID does not replace the disc identifier.

ISO revision 4 and nested ISO9660 revision 2 resolve shared-extent file aliases
by exact path, preserving distinct case-sensitive filenames. Metadata lookup
remains case-insensitive; it must not determine which bytes an inventory path owns.

PKGs write their own versioned pairs under `catalog/pkg/v6/`. Package metadata
includes content ID, title ID, content type, and available PSP title/version/firmware
fields. Whole-package SHA-256/SHA-1 identify the unchanged input. The website and
static export display packages under **psn**, alongside **umd**. Embedded PBP files
use the existing nested extraction pipeline when both catalog and store are set.
The PKG extractor supports retail PSP and PS1 packages, including standard PSP
theme packages (content type 9), not debug, native PS3, or Vita packages.
Themes may legitimately omit `PARAM.SFO`; no title metadata is invented. Present
malformed metadata still fails. Theme payloads retain their original bytes and
paths, including opaque PSPEDAT wrappers. Package decryption does not imply that every inner DRM payload is
supported: as with ISOs, a nested extractor failure fails that source's full ingest.

## PSN reference inventory and bounded acquisition

Inventory local PSP/PSX NoPayStation TSV snapshots without network access:

```sh
uv run --locked python tools/psn_acquire.py /path/to/tsvs \
  --work .work/psn-acquire --catalog catalog
```

The machine-local `report.json` accounts for every row across unique snapshots,
retains duplicate-source attribution and conflicting references, and excludes
license columns. Counts describe reference/package candidates, not a complete
enumeration of PSN. Missing hashes or sizes remain unknown.

Download a bounded batch from listed public Zeus URLs, then ingest separately:

```sh
uv run --locked python tools/psn_acquire.py /path/to/tsvs \
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
Other hosts and redirects remain explicitly unhandled rather than followed.

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

The website/export selects the highest numeric **complete** revision per source
hash, so old revisions do not create duplicate browser rows. An incomplete newer
pair does not hide an older complete result. Legacy `catalog/<extractor>/<hash>.json`
and `catalog/trees/<hash>.json` remain readable, but the status command reports
them as unversioned; regeneration writes versioned pairs and leaves them intact.

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

PSAR, NPUMDIMG, nested ISO9660, RCO, PRX/~PSP, SCE, PBP, gzip, KL3E and KL4E processing runs automatically during
ISO/PKG/ZIP ingest when both catalog and store are set:

```sh
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store
```

Detection uses signatures, independent of filenames. SCE borrows slices directly.
PBP extraction and embedded PKG metadata use Zig-PSP’s PBP reader in memory, with
borrowed slices and no temporary files. The pinned dependency receives a
[patch exposing its memory API and fixing bounds/final-section handling](tools/patches/zig-psp-pbp-memory.md). External tools extract into Zig-owned temporary directories;
Zig hashes/stores the output and queues nested extraction using retained buffers.
Temporary directories are removed after their immediate walk; children continue from
memory. An ISO is reported complete only after all its extraction jobs succeed.

Install `pspdecrypt` and the patched `rcomage` on PATH (overrides: `PSPDECRYPT`,
`RCOMAGE`). RCOMage loads INI files from `../share/rcomage` relative to its binary
(override: `RCOMAGE_DATA`). The Linux/LZR patch is in
`tools/patches/rcomage-lzr-linux.patch`.
Python adapters run through uv and are embedded in the ingest binary.

The main decrypter needs the standard update PRX recipe for tag `2E5E10F0`.
Build the pinned source with the repository patch (requires Git, Make, a C/C++
compiler, zlib and OpenSSL development headers):

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
title-specific key or sibling PBP section. PRX revision 2 records this recipe and
format-based ELF naming; PSAR revision 2 tracks the shared decrypter change.

PRX decryption preserves its decrypted payload; gzip payloads recurse to ELF.
KL3E/KL4E streams similarly retain their compressed bytes and get a decoded child.
ELF files containing bounded `~PSP` wrappers expose them as `embedded-<offset>.psp`
children, which recurse through the same decryption pipeline.
Executable children inherit their source basename for display and download, with
suffixes such as `.prx.gz` or `.prx.kl4e`; decompression removes the compression
suffix. Shared inventories retain canonical paths, so identical content can appear
under different filenames without conflicting catalog records.
RCO outputs include native resources and generated XML; provenance includes the
binary hash and configuration digest. Child failures fail their ISO's ingest.
`--skip-existing` skips an ISO only when its result and known reachable extraction
results are current. Current intermediate trees can be reused from the object store
while outdated descendants are extracted again. The thread
cap applies to ingest itself; external tools run in child processes.

KL decoding uses `pspdecrypt-kle` on PATH (`PSPDECRYPT_KLE` override): build
pspdecrypt with `tools/patches/pspdecrypt-kle.patch` and install that binary under
this separate name. The patch exposes standalone streams and adds decoder bounds
checks; it rejects outputs exceeding 64 MiB.

NPUMDIMG (`DATA.BIN`, PBP section 7) uses the existing pkg2zip decoder,
with a [standalone entry-point patch and build instructions](tools/patches/pkg2zip-npumdimg.md).
Install `pkg2zip-npumdimg` on PATH (`PKG2ZIP_NPUMDIMG` override). Ingest retains
`DATA.BIN`, attaches `disc.iso` beneath it, and inventories that ISO through
libarchive under the `iso9660` extractor. Its executable files recurse normally.
Derived ISOs stay beneath their PSN package rather than becoming UMD roots.
This disc decoder handles NPUMDIMG, not PS1 disc payloads or EDAT. PS1 executable
decryption and disc reconstruction use the whole-PBP helpers described below.
The PBP, ISO and PKG revisions were bumped to discover previously opaque children.

For NPUMDIMG PBPs, the Zig [DATA.PSP parser](tools/patches/data-psp.md) verifies the
SFO/content-ID signature using OpenSSL libcrypto. Generated verification reports
are not included in the extracted file inventory.
Install OpenSSL development headers/library when building ingest. Optional
STARTDAT and OPNSSMP containers are exposed without decoding their contents.

For supported PS1 PBPs, install [pspdb-pops](tools/pops/README.md) (`PSPDB_POPS`
override). It reads the full PBP to recover the sibling-derived title key, while
the catalog attaches decoded output specifically beneath `DATA.PSP`. The file
hash and download remain those of the original section. This contextual subtree
is stored in the PBP result, with helper provenance and normal decoded-file
hashes; it does not create a global standalone PRX result or a generated report.
Decoded ELF payloads use `.elf`, including PSP PRX modules. Gzip trees use the
`decoded_suffix` naming rule to retain that detected format in display names and
download filenames, without duplicating existing `.elf` suffixes.

PSN package labels use `XXXX-12345 Title`, with the serial styled like UMD IDs; collisions receive a short SHA-256
suffix that expands as needed. Full content IDs remain searchable. Hash-based
catalog identity and links remain stable when a display title changes.


PS1 PKG ingest uses Zig-PSP for PBP/SFO parsing and PSXtract-2 under Wine for
full disc reconstruction, attached beneath the original `DATA.BIN` section.
Configure `PSPDB_PSXTRACT2`, `PSPDB_WINE`, and optionally `WINEPREFIX`, or put
`psxtract.exe` and `wine` on PATH. See [PS1 extraction setup and validation](tools/psxtract/README.md).
