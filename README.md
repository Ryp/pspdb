# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extractor kind
and source hash owns revisioned inventories; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/PKG/NAND/updater-PBP/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. `catalog/` contains versioned metadata and inventories contributed through PRs.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.16.0**, GNU **patch**, **pkg-config**, and development headers/libraries
for **libarchive**, **OpenSSL 3**, **zlib** and **Expat**. PSAR filename-table
decryption also requires OpenSSL's **legacy provider** for DES-CBC.
Zig-PSP temporarily uses the local checkout at `../sudoku-zig/Zig-PSP`
(relative to this repository), including uncommitted changes. This is a working-tree
dependency, not an immutable revision pin. The first build fetches pinned
pspdecrypt, make-npdata, pkg2zip and RCOMage configuration sources.

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
combined summary. A failed folder does not stop the others. Source I/O, storage
integrity and catalog publication failures make the command exit nonzero.
Extractor failures are recorded in JSON instead of rejecting otherwise readable
sources. Overlapping folders are scanned as supplied, without deduplicating paths.

Discovers ISO and PKG files, including members of ZIP archives, plus uncompressed
NAND dumps and firmware updater PBPs as described below. Successful ISO
extraction requires `UMD_DATA.BIN` at the logical image root; recognized mastering
containers use their bounded `USER_L0.IMG` as described below. Missing or invalid
metadata is recorded as an extraction error once source identity is established. Retail PSP/PS1 PKGs
are decrypted by the native PKG extractor, preserving file and directory paths.
`--store` is optional. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips current
ISO/PKG/NAND/updater results when `--catalog` is set; it is **off by default**. Bump the affected extractor revision when extraction behavior changes.

Filesystem discovery stays parallel. Root intake concurrency is `max(1, N / 4)`,
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
ingest record. Successful results are immutable within a revision; conflicting
successful results raise `CatalogConflict`. A tree with an `error` string, including
an error in an inline extraction, is an incomplete attempt and may be replaced on
retry. Source metadata identity records remain immutable. New revisions preserve
previous successful results.
An empty, failed **derived** classification may be withdrawn by removing both
files of its pair. Source observations, partial inventories and successful results
cannot be withdrawn. The original file remains in its parent inventory.
The same bytes may have separate source roles: an original `iso` observation and
a nested `iso9660` extraction retain independent inventories and provenance.
Their SHA-256/size byte identity and stored object remain shared.
Inputs are read-only. Catalog JSON is tracked in Git; object stores and source
images stay local. See [CONTRIBUTING.md](CONTRIBUTING.md) to submit ingested content
and validate new metadata/tree pairs.

Failed extractors publish a nonempty `error` string on their extraction tree
(or occurrence-scoped inline extraction), for example `"error": "UnsupportedEdat"`.
The original file's path, size and hash remain cataloged, as do successful siblings.
An error is not a claim of successful decoding; failed authentication never
publishes unauthenticated plaintext. The website shows an error icon and message
on the affected file. External links stay beside the filename; errors and extractor
badges align at the right edge. Error-bearing results are never fresh for `--skip-existing`,
so supplying a missing helper or license allows a later run to retry them.

ISO revision 6, PKG revision 5 and PBP revision 4 read SFO strings through the first
NUL within the declared data length, allowing nonzero bytes after the terminator
found in retail metadata. Unterminated strings, unsupported text before the
terminator, and structural bounds violations remain errors. Earlier revisions stay unchanged.

SFO metadata is parsed in memory by Zig-PSP's `tools/sfo/src/main.zig`.
Its native reader validates bounds and borrows the key/data pools; PSPDB only
selects and validates its catalog fields. No SDK source patch is applied.

ISO titles share PKG's narrow legacy normalization: an otherwise ASCII `TITLE`
may contain CP1252 byte `0x99`, which becomes UTF-8 `™` in metadata only. Original
SFO bytes remain unchanged; other invalid high bytes are rejected. Generic PBP
and standalone updater validation retain their existing strict UTF-8 behavior.

ISO revision 6 and nested ISO9660 revision 4 preserve valid UTF-8 filenames
verbatim. Invalid-UTF-8 Rock Ridge names are converted strictly from CP932;
undecodable input and unsafe paths remain errors. Shared-extent aliases retain
byte-exact, case-sensitive target lookup.

A mastering wrapper must contain exactly four regular root files:
`CONT_L0.IMG`, `MDI.IMG`, `UMD_AUTH.DAT` and `USER_L0.IMG`. The reader validates the
inner ISO's bounds and checks that libarchive's effective file view agrees with
the borrowed extents. Metadata comes from the logical image and records
`logical_image_path: "USER_L0.IMG"`. The outer SHA-256, SHA-1 and size remain
unchanged; all four outer files remain visible, and the inner image gets its own
hash-keyed ISO9660 inventory. An ordinary root `UMD_DATA.BIN` takes precedence.

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
the **psp** root row: its size column sums original ISO/PKG/NAND/updater sizes without counting
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
malformed metadata records an extraction error. Theme payloads retain their original bytes and
paths, including opaque PSPEDAT wrappers. Package decryption does not imply that every
inner DRM payload is supported: nested extraction failures are recorded on their
trees without discarding the package inventory.

## NAND dumps

NAND revision 1 uses the local Zig-PSP library directly. Supported raw sizes are
34,603,008 and 69,206,016 bytes: 2,048 or 4,096 blocks, each containing 32 pages
of 512 data bytes plus 16 spare/ECC bytes. The entire unchanged raw dump determines
its SHA-256, SHA-1 and size. Records and inventories are written under
`catalog/nand/v1/<raw-sha256>-ingest.json` and `<raw-sha256>-tree.json`.
Immutable metadata contains geometry only, never key-dependent extraction results.

Suffix matching is case-insensitive. Explicit `.nand` files are observed even when
damaged or incorrectly sized; supported-size `.bin` files require an ECC-corrected
IPL-table or IdStorage marker. Markerless `.bin` files are ignored. ZIP discovery
remains ISO/PKG-only; compressed NAND and compressed updater PBP inputs are not recognized.

For encrypted regions, set `PSPDB_NAND_FUSE_DIR`, or use the default
`${XDG_DATA_HOME:-$HOME/.local/share}/pspdb/nand-fuses`. Each private key is named
`<raw-sha256>.fuse` and contains exactly 16 hexadecimal digits, optionally followed
by one LF or CRLF. No `0x` prefix or whitespace trimming is accepted. Keep key
directories/files private (0700/0600), outside inputs, catalog and CAS.
Key files are opened no-follow/nonblocking; their contents never enter metadata,
provenance, filenames or logs. Missing keys allow plaintext regions to survive.
Invalid present keys record `InvalidNandFuseId` while independent extraction continues.

PRX revision 10 also uses this private fuse context to remove installed-module
signcheck protection with the SDK's real KIRK CMD8 implementation. The derived
key belongs to one ingestion group, is shared immutably with recursive PRX jobs,
and is cleared only after its last job finishes. Task copies and catalog/CAS
metadata never contain it. Ordinary PRXs are decoded unchanged first: nonzero
signcheck bytes alone do not prove that a module needs normalization.
When ordinary decoding fails on a signcheck candidate, missing context reports
`MissingNandFuseId`. With a key, the extractor restores an owned copy of
`0x80..0x150`, then revalidates the restored size/tag through the native decoder.
Original source bytes and hashes remain unchanged. CMD8 itself does not
authenticate; the native decoder's integrity limitations below still apply.
Supplying the key and rerunning with `--skip-existing` retries incomplete roots
and failed child trees; adding a key does not trigger retries within a running job.

Native extraction independently reconstructs `ipl.bin`, every valid
`idstorage/index-<physical-block>/index.bin` and live leaf, and all actual
`lflash/flashN.img` partitions. IPL records/images/stages and formatted FAT contents
are occurrence-scoped inline trees with shared `pspdb-nand` provenance. Unformatted
partitions remain images. Unverified IPL plaintext is diagnostic-only and is not
cataloged or stored. Native extraction runs with or without `--catalog`; ordinary
extracted files use the existing recursive pipeline when a catalog is configured.

`--store` persists all real extracted artifacts, including IdStorage/settings,
but **never adds the original raw NAND**. A store-backed website applies its existing
download policy to those artifacts. Raw downloads are unavailable unless the raw
object independently exists in that store. No privacy filter or new access-control
policy is applied.

The website groups one full-hash observation under **firmware/nand**, labels the
data geometry as 32/64 MiB, and displays the full 33/66 MiB raw size without descendant
inflation. Firmware updater PBPs occupy **firmware/update**; **psn/update** is unchanged.
Native region/inline errors retain successful siblings. Any reachable stale or failed
decoder keeps the NAND root non-fresh and eligible for `--skip-existing` retries.
Keys are not freshness dependencies, and incomplete retries cannot replace a
previously successful tree.

## Firmware updater PBPs

Update revision 2 recognizes regular, uncompressed `.pbp` files (case-insensitive)
with a valid PBP layout, a nonempty UTF-8 `UPDATER_VER` in `PARAM.SFO`, and a final
`DATA.BIN` section beginning with `PSAR`. Other PBPs and malformed probes are ignored.
Recognition does not authenticate a release or infer a model/version from its filename.

The entire unchanged PBP determines its SHA-256, SHA-1 and size. Root observations
live at `catalog/update/v2/<raw-sha256>-ingest.json` and `<raw-sha256>-tree.json`,
with `pspdb-update` provenance. Metadata records the observed updater version,
title and disc ID when present; `DISC_VERSION` is not the target firmware version.
Different hashes remain distinct even when their version labels match.

`metadata.updater_target` (also `updater_target` in CLI JSON) records the declared
compatibility class from the same SFO parse: four-byte integer `BOOTABLE` (`0x0404`)
value 1 gives `"psp"` (non-Go), and value 2 gives `"psp-go"` among released PSP
hardware. Missing `BOOTABLE` or another valid uint32 value gives explicit `null`,
not non-Go. Duplicate keys, wrong types and wrong integer widths reject the updater
probe like malformed selected string metadata. Generic PBP parsing is unchanged.
This declaration is not authenticity, payload verification or installation safety;
unreleased/test model assignments are outside the released-hardware interpretation.

Revision 1 observations remain immutable and may omit this field. After rebuilding,
refresh into revision 2 with
`uv run --locked ./ingest/zig-out/bin/pspdb-ingest /path/to/updaters --catalog catalog --skip-existing`.
Omit `--store` to leave the existing CAS untouched; original PBP inputs are read-only.
The website appends `Go` after the version when `updater_target` is `"psp-go"`; non-Go and unknown targets have no suffix.

The native PBP walker emits the original section names and exact byte slices,
including `DATA.PSP` and `DATA.BIN`. Queued sections retain the read-only source
mapping; only the small SFO metadata buffer is copied. Immediate inventory works
without a catalog. With a catalog, sections enter the existing recursive pipeline,
including PSAR extraction. `--store` persists extracted artifacts, not the raw PBP.
Root downloads require that raw object to exist independently in the store.

The website places these observations under **firmware/update**, labelled
`Update <observed version> · <short hash>`, with full-hash `.pbp` routes and raw
sizes that do not include descendants. Nested generic PBP observations retain
their separate inventories and freshness roles. **psn/update** is unchanged.
Reachable extraction errors preserve successful contents and keep the updater
eligible for `--skip-existing` retries.

PRX revision 12, gzip revision 4, KL3E/KL4E revision 5 and PGD revision 4 use
filename-independent output names in hash-keyed trees. Occurrence naming rules
restore source-specific display/download names. This prevents catalog conflicts
when identical firmware components occur under different names or ELF offsets.
Historical revisions remain unchanged.

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
# Add --json for per-source provenance and affected ISO/PKG/NAND/updater hashes.
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store --skip-existing
```

The status command is read-only. It compares revisions, executable SHA-256 hashes,
and extraction options (including the RCOMage INI digest), and follows child hashes
to report affected ISO, PKG, NAND and updater roots. Missing tools are reported as unavailable, never current.
If a tool/configuration changes within the same revision, bump that extractor's
revision before regenerating successful results; those results will not be overwritten.
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

The website/export selects the highest numeric **complete metadata/tree pair** per
extractor kind and source hash, so old revisions do not create duplicate browser rows.
An error-bearing tree is still a published pair, not a successful extraction. An incomplete newer
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
Store availability checks have a 15-second deadline per batch. A stalled request
shows **Check failed**, not **Missing**, and does not block later batches. Reload
the page to retry failed checks after restoring access to the store.
Add `--umdatabase /path/to/pages` for exact SHA-1 links from saved UMDatabase
entry pages named `ID.html` (for example, `E39CFE68.html`).
UMD video labels use the SFO title when available, otherwise the observed disc
identifier. Missing optional SFO metadata does not prevent browsing its inventory.
The API and exported `catalog.json.gz` keep inventories in `trees[kind][sha256]`.
Root rows use their explicit `iso`, `pkg`, `nand` or `update` inventory; nested
files use their derived extractor inventory. Inline contextual extractions retain occurrence precedence.

The local server caches compact catalog JSON, gzip bytes and the download index
as one coherent snapshot. Requests recheck catalog paths, modification/change times,
sizes, inode identities and annotation dependencies at most once every five seconds. One background
refresh runs at a time; requests can use the previous snapshot for up to 30 seconds
after its last successful check. Cold or expired requests wait for regeneration.
Refresh errors are logged and return HTTP 500 rather than hiding failures behind
an indefinitely stale catalog. Conditional requests use representation-specific
ETags, so unchanged reloads can return HTTP 304 without transferring the catalog.
Availability checks still inspect requested store objects live.

Completed, stable snapshots are also cached outside `catalog/`, under
`$XDG_CACHE_HOME/pspdb/web` (default `~/.cache/pspdb/web`). Set
`PSPDB_WEB_CACHE_DIR` to choose another directory, or to an empty string to disable
disk caching. A restart reuses the compressed snapshot only when source signatures,
annotation mappings, download mode and viewer implementation still match. Cache
files are private, atomically replaced and checksum-checked; missing, corrupt or
unwritable caches fall back to the authoritative catalog. Invalid catalog data
still fails validation. A source change during generation prevents publishing that
generation to disk. This cache is disposable, not another catalog or database.

The browser constructs the tree in yielding batches, retains compact occurrence
identities and computes paths only when needed. A Web Worker searches and sorts
an interned text/typed-array index without blocking keyboard input. Superseded
queries are cancelled; no results are dropped or capped. Only viewport rows are
mounted, and scaled scroll coordinates keep the final rows reachable even beyond
browser layout-height limits. Search covers files inside collapsed branches;
narrowing a query reuses matches and checks only the surviving candidates' strings,
memoizing repeated lookups and skipping already-satisfied terms. Broadening searches
the full index.
Hash-only terms (8–64 hexadecimal characters, case-insensitive) match each file's
own SHA-256, not hashes inherited from parent containers. Matching occurrences
remain separate; ordinary text and filename searches include ancestor context.
The same worker is included in static exports; serve them over HTTP as below.

On narrow screens, the viewer prioritizes names and sizes, shows search-result
filenames instead of long ancestor paths, and keeps the full selected path, exact
byte count, and extraction details below the tree. **Copy SHA-256** replaces the
narrow-screen hash column; **Open in tree** opens a search result without a double
tap. Touch pointers get 44-pixel controls and taller rows, with virtual scrolling
adjusted to the actual row height. Desktop columns and keyboard navigation remain
available; selecting an error reveals its full message on either layout.

On a frozen 1,654,763-file catalog, Chromium measurements on a Ryzen 9 5950X
showed search results in 21–64 ms versus 371–751 ms before these changes, with
matching result counts. Main-thread heap fell from about 2 GB to 240 MB, plus
about 115 MB for the worker and its typed-array index. Static catalog readiness
improved from 4.9 to 2.9 seconds; the longest main-thread task fell from 4.5 seconds
to 225 ms. These are local measurements, not latency guarantees.

On a later 3,022,137-file snapshot, candidate-only string matching reduced median
incremental search time over three Chromium runs: `eboot` → `eboot.bin` from
37.5 to 13.1 ms, adding `psp_game` from 48.0 to 13.8 ms, and extending an
eight-character hash prefix to twelve characters from 29.3 to 0.8 ms. Result counts
matched; these timings include installing the results, not just worker execution.

On a later frozen catalog with 40,934 JSON files and a 155 MB response (45.5 MB
gzip), catalog preparation took 3.81 seconds without a disk cache and 0.52 seconds
with a matching snapshot after restart. A fresh server's first gzip response began
in 0.54 seconds. This measurement had downloads disabled; enabling downloads also
requires rebuilding their lookup index from the cached JSON. First builds and
changed catalogs still require scanning and parsing the source files. The design
avoids a separate database/index service and trades bounded refresh delay for fast
warm requests; it does not remove the initial browser download or indexing cost.

## Static hosting / GitHub Pages

```sh
uv run --locked pspdb-web export --catalog catalog --output dist/site \
  --redump /path/to/redump.dat.zip \
  --umdatabase /path/to/umdatabase/pages
uv run --locked python -m http.server --directory dist 8001
```

Open `http://localhost:8001/site/`. The output directory must be empty. Supply the
reference inputs on **every publication**: export does not discover or fetch them
automatically, and omitting a flag omits that source's UMD associations. Redump
matches require exact SHA-1 and size; UMDatabase matches require exact disc SHA-1.
Coverage depends on the supplied snapshots. Bundled PSX Redump associations are
included separately. Export leaves ingested records unchanged and publishes only
browser assets and metadata; Store/downloads are disabled. Relative asset URLs
support repository paths such as `/pspdb/`.

Static exports contain `catalog.json.gz` rather than uncompressed JSON, keeping
large snapshots below GitHub's 100 MiB per-file limit. The viewer decompresses it
with the browser's native `DecompressionStream` API before building its index.
Serve this file as gzip data (for example, `application/gzip`), not as an already
HTTP-decoded JSON response. Python's static server and GitHub Pages serve it this
way without additional configuration.

While loading, the viewer shows download progress and received bytes, with a
percentage when the response provides a usable length. Unknown-length or
HTTP-decoded responses use an indeterminate bar instead of an inaccurate
percentage. After transfer, the status changes to “Preparing catalog…” until
the tree is ready; failed transfers show an error rather than a completed bar.

Keep source code on `main` and exported snapshots at the root of a separate
`pages` branch (`index.html`, assets, and `catalog.json.gz`, without a `site/` wrapper).
Export into an empty staging directory, then copy its contents into a separate
clone of that branch. Never switch branches in a checkout used by active ingestion.
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

The ingest CLI tests build the current executable and generate their own ISO/PKG/NAND/PBP/ZIP
fixtures. PKG fixtures use OpenSSL for independent AES encryption; NAND fixtures
use synthetic markers and partitions, never private dumps or fuse IDs. Updater
fixtures exercise native PBP/PSAR recursion, retained source ownership and shared-byte naming.

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
supported NPD EDAT, fixed-key `OPNSSMP.PGD` and legacy DOCUMENT processing runs
when a catalog is set, with or without a content store:

```sh
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog
```

PSMF/PMF movies and raw MPEG program streams remain opaque source files; no movie subtrees are generated.

Detection uses signatures except that generic PGD dispatch is restricted to the
known `OPNSSMP.PGD` basename. SCE borrows slices directly.
PBP extraction and embedded PKG metadata use Zig-PSP's native PBP memory API,
with borrowed slices, validated bounds, complete final-section handling and no
temporary files. PSPDB imports the SDK source directly. Remaining external tools
receive input bytes in private temporary directories, not by reopening CAS objects.
Zig hashes their outputs and queues
nested extraction using retained buffers; `--store` additionally persists those bytes.
Temporary input/output directories are removed after the immediate walk.
Retail PKG keys and offset AES-CTR, plus NPUMDIMG metadata hashing/signature
verification, live in Zig-PSP's `tools/prxencrypt/pkg_crypto.zig` and
`npumdimg_crypto.zig`. PSPDB retains container parsing and catalog policy.
The NPUMDIMG verifier uses the SDK's shared native `kirk` module, not OpenSSL EC.
Paired manuals retain their exact input and companion views until contextual extraction.
An ISO is reported complete only after all its extraction jobs succeed.

The Zig inventory model lives in `ingest/src/inventory.zig`: source results,
entries, contextual dependencies, serialization and owned-data cleanup.
`processor.zig` performs extraction/inventory work; `catalog.zig` publishes that
model without depending on the processor. Scheduling remains in `ingest.zig`.
`bytes.zig` owns shared backing lifetimes. `Owner.take_allocated` and
`Owner.take_mapped` consume their input even if owner allocation fails; callers
release the returned view, never separately free its backing.
`gzip.zig` owns complete-stream and bounded single-member decompression;
`containers.zig` only exposes borrowed container slices. PRX calls the codecs
directly, keeping its declared-size and authentication boundaries explicit.
Native source normalization and patch lists live in `ingest/build.zig`;
`tools/prepare_native.py` applies the shared preparation steps without mutating
the fetched dependencies. Standalone builders explicitly opt into patching
their already isolated temporary source directory.

PSAR revision 4 runs the pinned pspdecrypt algorithms through a native memory
bridge. It preserves final-write semantics, decoded table lengths, secondary
compression members, reboot modules, IPL stages and kernel-key outputs.
Authenticated IPL kernel-key output may contain one 16-byte key or at least two
keys. The second-key XOR is applied only when those bytes exist; shorter output
and a partial second key remain errors. Original PSAR framing and suffix bytes
are not rewritten.
The collector retains at most 8 MiB of output payloads. Larger archives retain
only final names/event positions and replay the immutable source to emit final
writes; this is a buffering policy, not an output-size limit or a process-wide
memory cap. The first complete walk must succeed before any output is emitted.
Consumers borrow names/views until their callback returns and retain a view
when its bytes must outlive that call.

The build uses pspdecrypt commit `c156627db7634d395c380c0a9589130f603307fc`,
shared PRX recipes and bounded per-call IPL state. DES uses a private OpenSSL
legacy-provider context; KIRK state remains thread-local. The former custom
SHA-256 variant is standard SHA-224, including its 28-byte output.
Decoded package tables describe model selection, not a complete installed
firmware filesystem.

RCO revision 2 uses `rco/model.zig` for bounded resource/tree parsing,
`rco/config.zig` for pinned configuration and `rco/xml.zig` for byte-compatible
serialization. These are LGPL-2.1 ports of RCOMage
`54ca649a9a6aba150a1fbe423f4c3aec611ee913`. The build embeds its six INI files;
there is no runtime configuration discovery. Raw assets borrow their backing;
decompressed resources and XML have explicit owned buffers. Expat validates XML
without a second DOM or a new depth limit. As with the former dumper, large valid
trees can expand substantially when serialized; no new XML output-budget policy
is imposed.

PSAR/RCO no longer use `pspdecrypt`, `rcomage`, their environment overrides or
temporary extraction directories. Only PSX and DOCUMENT retain external
Python adapters, embedded in the binary and run through uv.

PRX and KL3E/KL4E decode in memory through a pinned, patched pspdecrypt library
linked by the Zig build. They need no external helper, NAS input reread, or
temporary output files. This links GPLv3 pspdecrypt code into the ingest binary.
PRX revision 12 supports `~PSP` modules and `PSPsysGP` firmware resources,
with layouts 0/1/2/4/5/6; legacy layout 8 shares the layout-0 algorithm.
Coverage includes standard update XOR recipes and Go firmware index keys.
Known resource tags select an exact recipe, and integrity failures are terminal.
KIRK1 verifies the required CMAC or both ECDSA signatures before returning
plaintext; type-6 verification uses correctly sized 21-byte curve scalars.
Mutable KIRK state is thread-local. No unchecked payload-only fallback remains.
Separate outer Sony signature fields are not verified: valid inner authentication
does not establish whole-updater authenticity or installation safety.
Once a recipe's outer header hash matches, failed KIRK integrity is reported as
`PrxIntegrityFailed`; it cannot fall through to console-signcheck normalization
or become a misleading missing-fuse dependency.

Generic layouts 3/7/10 and runtime-key-dependent PAUTH/NPDRM modules are not
supported by the standalone PRX path. PAUTH needs the game's runtime work area;
NPDRM can require a per-module key. Fixed XOR constants do not replace those keys.
ARK's custom gzip/MD5 wrappers are not authenticated PRX envelopes and remain
unsupported; they are not silently inflated.

`OPNSSMP.PGD` revision 4 authenticates and decrypts the observed version-1,
DRM-type-1 profile in memory with the fixed DNAS key. The decoder validates the
DNAS header MAC, derived-key header, complete block-MAC table and every ciphertext
block before publishing the exact plaintext as `OPNSSMP.EXT`, where `EXT` is
inferred from the plaintext signature. Generic PGD filenames remain opaque; their
key context is not inferred from matching bytes alone.
Supported POPS executables use the native contextual decoder with their DATA.BIN sibling.

PRX preserves gzip- or KL-encoded ELF as a separate recursive extraction layer.
Occurrence names are `SOURCE.elf.gz`, `SOURCE.elf.kl3e` or `SOURCE.elf.kl4e`;
hash-keyed trees retain generic, filename-independent payload names.
Gzip and standalone KL identify the decoded format and use `decoded_suffix`
occurrence naming: remove a matching compression suffix case-insensitively,
then retain the decoded extension without duplicating an existing `.elf`.
Missing, mismatched or suffix-only names do not prevent decoding.
For example, the extraction chain is
`OPNSSMP.psp` → `OPNSSMP.elf.kl4e` → `OPNSSMP.elf`.
PRX continues to expand contained 2RLZ data directly.
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

Standalone gzip revision 4 uses Zig's standard-library DEFLATE decoder on the retained
input buffer, without a Python process, NAS input reread, or temporary output
files. Each member's CRC32 and decoded size are checked before any output is
published; concatenated members and zero padding retain Python gzip behavior.
A validated gzip prefix followed by a non-gzip suffix makes the entire input
opaque: the original file remains intact, with no decoded prefix or gzip tree
published. Classification happens during the deduplicated decode, not a second
inflate probe. Recognized later members still require valid headers, DEFLATE,
CRC32 and size; truncation remains an error. Destroyed next-member magic cannot
be distinguished from an enclosing-format suffix. Historical empty failed
classifications must be withdrawn as complete pairs to prevent stale fallback.
A standalone stream's decoded child is named `module.elf`, `payload.gz`, or `payload.bin`
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
binary hash and configuration digest. Child failures are recorded on their extraction trees.
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

License-2 EDATs select a regular, nonsymlink, exactly 16-byte
`<NPD-content-id>.rap` from the shared license directory described above.
Override that directory with `PSPDB_RAP_DIR`; otherwise `XDG_DATA_HOME` or
`~/.local/share/pspdb/licenses` supplies the default. License bytes never enter
catalog JSON or provenance. Missing/invalid licenses and failed authentication
produce an EDAT extraction error, without rejecting the parent inventory or
publishing plaintext.

EDAT revision 3 also recognizes the authenticated empty `ISO.BIN.EDAT` markers
shipped beside `PBOOT.PBP` in PSP update packages. These NPD v2/license-3/flags-0x0c
files use an all-zero developer klicensee, require no RAP, and decrypt to an empty
payload. Their keyed filename, content-ID, developer, metadata and header fields
still authenticate; arbitrary license-3 payloads remain unsupported.

EDAT extraction otherwise supports license-2 NPD v1/flags-0 and
v2/flags-0-or-0x0c files, with 16 KiB blocks and at most 64 MiB plaintext. Keyed
header, metadata-table and every ciphertext-block MAC must pass before publication.
The original EDAT, including signatures and any optional 16-byte footer, stays
unchanged; the decoder does not verify filename-dependent hashes or ECDSA signatures.
Its sole child is `payload.DAT`, displayed and downloaded using the EDAT source
stem: `ISO.BIN.EDAT` yields `ISO.BIN.DAT`, and `MINIS.EDAT` yields `MINIS.DAT`.
Recognized payload formats still recurse through their registered extractors.

Big-endian NPUMDIMG metadata does not contain an identified filesystem.
It remains a single DAT file for inspection or a future extractor, rather than
being split into synthetic header fields and block records. It is not sent to
the little-endian NPUMDIMG disc decoder. International Snooker (EU) exercises
both payload sizes: 80-byte `MINIS.DAT` and 116,704-byte `ISO.BIN.DAT`.
Original EDAT and decrypted DAT bytes are retained unchanged.

For NPUMDIMG PBPs, the Zig [DATA.PSP parser](tools/patches/data-psp.md) verifies the
SFO/content-ID signature through Zig-PSP's native KIRK curve implementation.
Generated verification reports are not included in the extracted file inventory.
Other native extractors still require OpenSSL development headers/library.
Optional STARTDAT containers remain opaque; supported fixed-key `OPNSSMP.PGD`
children are authenticated and decoded by the separate PGD extractor.

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
Synthesized extensions are lowercase. Existing container member names and names
retained by stripping compression suffixes preserve their original case.

PSN package labels use `XXXX-12345 Title`, with the serial styled like UMD IDs; collisions receive a short SHA-256
suffix that expands as needed. Full content IDs remain searchable. Hash-based
catalog identity and links remain stable when a display title changes.


PS1 PKG ingest uses Zig-PSP for PBP/SFO parsing and native Linux PSXtract-2 for
full disc reconstruction, attached beneath the original `DATA.BIN` occurrence.
Set `PSPDB_PSXTRACT` or put `pspdb-psxtract` on PATH. The native helper includes
the exact ATRAC3 decoder; Wine and external audio-converter executables are not used.
PSX remains a file-based helper. See [PS1 extraction setup and validation](tools/psxtract/README.md).

External helper execution requires Linux `/proc/self/fd`. Ingestion holds an open
executable descriptor across provenance queries, hashing and launch for both PSX
and DOCUMENT, so atomic helper replacement cannot mix versions within one
extraction. Publish helper updates atomically; modifying an executable in place
is not protected by this descriptor pinning.

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

The patched readers borrow the supplied source bytes and decode one page at a
time. Pillow validates each unchanged PNG in memory before the helper writes it
directly into its private publication directory. Readers no longer reopen source
snapshots, reconstruct unused DAT buffers or write intermediate PNG trees.
DOCUMENT remains an external Python helper: the ingestion adapter still stages
its explicit inputs and consumes the published page files.

DOCUMENT revision 3 records this byte-input/callback implementation separately
from earlier revision 2 helper provenance. ISO/PKG revision 4 and nested ISO9660
revision 3 provide new namespaces for inventories embedding paired manual results.
Keep historical records intact: different helper hashes/options must not overwrite
successful results at the same revision. Rebuild the ingester after updating
`tools/extractor_versions.json`; build/configure the helper above before ingesting.
The first run at these new revisions reprocesses affected source kinds even with
`--skip-existing`; it adds new pairs without replacing the older revisions.

Fixed-key recognition uses the encrypted DOC magic/version block, not filenames
or generic PGD magic. The reader checks supported header/table/page protection;
these are source-consistency checks, not independent trusted-origin authentication.
Extraction preserves the wrapper and exact PNG bytes. Neutral `psp/001.png` and
`ps3/001.png` paths retain each platform's page ordinals, including shared frames.
The helper emits a JSON source/page map on stdout, including original source
identity and frame offsets/sizes/hashes. This generated metadata is not an
extracted file; the output directory and DOCUMENT inventory contain only page PNGs.

All expected pages must pass PNG CRC, end-boundary and pixel decoding checks before
atomic publication. Late-page failure leaves the caller's output empty and records
an extraction error in the parent inventory. No whole-disc reconstruction or inferred PBP key is used.
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

