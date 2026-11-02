# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extractor kind
and source hash owns revisioned inventories; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/PKG/NAND/updater-PBP/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. `catalog/` contains versioned metadata and inventories contributed through PRs.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.17.0**, GNU **patch**, **pkg-config**, and development headers/libraries
for **libarchive**, **zlib** and **Expat**.
Zig-PSP temporarily uses the local checkout at `../Zig-PSP`
(relative to this repository), including uncommitted changes. This is a working-tree
dependency, not an immutable revision pin. PRX, PSAR, KL3E/KL4E, PGD, POPS and
EDAT-key decryption use its pure-Zig ports (`tools/prxencrypt`, GPL-3.0). The first
build fetches pinned make-npdata, pkg2zip and RCOMage configuration sources.

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
`--store` is optional. `--store-max-size SIZE` (bytes, or a binary `K`/`M`/`G`
suffix such as `64M`) keeps larger objects out of the store; they are still hashed,
cataloged and extracted, but are not downloadable, and `--skip-existing` cannot reuse
a nested tree containing them. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips current
ISO/PKG/NAND/updater results when `--catalog` is set; it is **off by default**. Bump the affected extractor revision when extraction behavior changes.

`--rap-output DIR` additionally writes the licence key (RAP) that ingest derives from each
PSN package's own `EBOOT.PBP` (see [EDAT keys](#edat-keys-derived-from-the-package)) as
`<CONTENT_ID>.rap`, exactly 16 bytes. `DIR` is created mode 0700 when missing and files are
0600, written atomically and never overwritten: an identical existing file is left alone, a
different one is reported on stderr (content ID only) and kept. Without the option no RAP file
is written; packages skipped by `--skip-existing` are not read, so they write none either.
It does not need `--catalog`. Key bytes are never printed or logged.

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
may contain CP1252 bytes `0x99`, `0xA9`, `0xAE` and `0x92`, which become UTF-8
`™`, `©`, `®` and `’`, and the Shift-JIS pair `0x81 0x45`, which becomes `・`,
in metadata only (ISO 7, PKG 7 and PBP 5 added `©` and `®`; `’` and `・` were
added within those revisions because they only turn former `InvalidSfo`
errors into results, which `--skip-existing` retries anyway). Original
SFO bytes remain unchanged; other invalid high bytes are rejected. Nested PBP
`PARAM.SFO` validation applies the same title rule since PBP revision 5;
standalone updater validation retains strict UTF-8.

A PKG that fails extraction (unsupported platform, invalid or missing
`PARAM.SFO`, …) still records its unencrypted header identity when the header
is readable: `metadata` then holds only `content_id`, `title_id`, and
`content_type`/`package_flags` when declared. Successful packages are unchanged,
so this needs no revision bump either.

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
**theme** (9, within supported PSP packages). Content type 7 with outer `PARAM.SFO`
`CATEGORY` `HG` selects **pcengine**. Missing or unrecognized types fall under **unknown**; empty groups
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
  --work .work/psn-acquire --packages /path/to/packages \
  --catalog catalog --category PSP_DLCS --limit 5
./ingest/zig-out/bin/pspdb-ingest /path/to/packages \
  --catalog .work/psn-catalog --store /path/to/store
```

Two directories, deliberately separate. `--work` is machine-local bookkeeping: the
lock, `state.json`, `report.json` and the TSV snapshot cache. `--packages` holds
packages and nothing else — one `<sha256>.pkg` per package, no JSON, no lock, no
scratch subdirectory — so it can live on slow or shared storage and be handed
straight to `pspdb-ingest`. It defaults to `<work>/packages`.

The name is the identity: the SHA-256 of the file's own bytes. The size is not in
the name because `stat` already reports it, and the PKG header declares it too.

Transfers happen entirely in memory. A package is buffered, hashed and validated
before anything is written, then published with a single fsynced write to a hidden
temporary beside the target followed by an atomic rename. Nothing partial ever
appears in the package directory, there is no `.part` file, and no file is read
back to hash it. The cost is that an aborted transfer has nothing to resume:
the next run starts that package again. Transfers are capped at 4 GiB, refused
before the request when the reference size already exceeds it and aborted with
status `too_large` if a response tries to exceed it mid-stream.

Acquisition defaults to one transfer. Set `--workers 8` for up to eight concurrent
PKG transfers; `--limit` still caps total attempts, including local reuse.
`--memory-gib 4` (the default) bounds the sum of reserved in-flight payload bytes,
not process RSS: Python buffers, allocator and socket overhead require extra RAM.
Known sizes reserve their full size before starting; unknown sizes conservatively
reserve the smaller of the shared budget and the 4 GiB per-package ceiling.
The memory budget can therefore reduce effective concurrency. Packages larger
than either limit report `too_large`; increasing the shared budget does not raise
the per-package ceiling.

For example:

```sh
uv run --locked python tools/psn_acquire.py \
  --work .work/psn-acquire --packages /path/to/packages \
  --catalog catalog --limit 10000 --workers 8 --memory-gib 4
```

Stop an existing acquisition before restarting with these options. Ctrl+C stops
scheduling and cancels active transfers between reads or retry waits, then joins
them before writing the final report and exiting with status 130. A blocked
network operation may need to return or time out first. Completed packages remain;
incomplete transfers restart on the next run. Do not run separate work directories
against the same package directory concurrently.

Acquisition uses finite retries/timeouts, preserves 2 GiB free by default, and
serializes publication so concurrent writers cannot race its free-space checks.
It publishes `.pkg` files only after PKG-header and supplied size/hash
checks. Missing reference hashes never become hash-confirmed. Repeated runs reuse
packages already present. Use `--package` with a report candidate ID for exact
selection, `--reuse` for existing local packages, and `--retry-failed` to revisit
permanent failures.
Supported sources are `zeus.dl.playstation.net/cdn/` and the update host
`b0.ww.np.dl.playstation.net/tppkg/np/`. Host-specific paths, public DNS targets,
and credential-free URLs are enforced. Other hosts and redirects remain
explicitly unhandled rather than followed.

Acquisition reports progress on stderr while stdout stays a single machine-readable
JSON object. With `--workers 1`, a terminal gets one repainted line per package with
the attempt counter, package name, transferred share and a recent-window transfer rate:

```text
[3/25] Patapon 2 [UP0001-TEST00001_00-ABCDEFGHIJKLMNOP]   43% 3.0 MiB/7.0 MiB 4.0 MiB/s
```

A redirected stderr gets plain `start` and result lines per package instead, with
the elapsed time, average rate, and the failure status and cause when one applies.
With multiple workers, terminals also use these stable lines; completion order can
differ from start order. There is no live aggregate rate display.
The counter's denominator is the number of packages this run plans to attempt,
which is `--limit` bounded by the candidates left after filtering. Single-worker
live rates use a five-second window, updated as transfer progress arrives.
`--no-progress` disables the log; it never affects stdout, `state.json` or
`report.json`.

Startup is reported too, because it is slow enough to look like a hang before any
download begins: fetching each TSV, reading the snapshots, scanning the catalog,
and checking the packages already in `--packages`.

That check does not re-hash anything. A stored file is named `<sha256>.pkg` by this
tool only after its bytes were hashed and verified in memory, so the published name
*is* the identity; startup reuses the identity recorded in `state.json` when the
name and on-disk size still agree, and otherwise reads the 128-byte PKG header and
compares the header's declared total against the file size. Files that are
truncated, resized or headerless are quarantined beside themselves as
`<sha256>.pkg.corrupt`, which no longer matches `*.pkg`. Downloads therefore begin
in seconds instead of waiting on a full pass over the store; `report.json` records
`"identity_basis": "published_name"`.

`--verify` restores the exhaustive pass, re-hashing every stored package to detect
silent corruption that happened after publication. It repaints a counter, digest
prefix and hashing rate per file, and reports `"identity_basis": "hashed_bytes"`:

```text
[21/322] 10c58a42dd9d128f                              63% 640.0 MiB/1.0 GiB 108.3 MiB/s
```

Under `--verify` each file is hashed at most once per run: the closing
reconciliation reuses the opening pass for files whose size and mtime are
unchanged, and re-hashes any file that changed underneath it.

`Ctrl+C` stops after the chunk in flight rather than aborting the process. The
in-memory buffer is discarded, the remaining candidates are left untouched,
`state.json` and `report.json` are still published, the final JSON object is still
printed with `"interrupted": true`, and the exit status is 130 with no traceback.
The interrupted package keeps status `interrupted`, which is retryable without
`--retry-failed`; the next run transfers it again from the start.

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

`--skip-existing` uses uv/Python for the read-only provenance scan at startup; this is the
only Python in the ingest.
Affected ISOs are read again, while current intermediate
extractions reuse stored child bytes. Missing stored children cause that
extractor to run again. Source ISOs/ZIPs must still be available; this command does
not regenerate arbitrary sources directly from the object store. Without
`--skip-existing`, all encountered sources are processed as before.

Reuse does not re-hash the object store. New objects are written unsynced to
`<store>/.incoming` and published in batches (up to 4096 objects or 1 GiB, and
always before a root's catalog record): one `syncfs` makes the whole batch durable,
then each object is renamed to `sha256/aa/bb/<digest>` without replacing an
existing object. A name therefore only appears once its contents are durable, and
the digest in the path is its identity. One filesystem sync per batch replaces one
fsync per object, roughly halving write operations on an HDD-backed btrfs store.
Readers check presence and exact size only: rehashing every
reused child would read the whole store on each run, which is the dominant cost
on spinning disks. A stored size that disagrees with the record is damage rather
than a stale name, and fails the run with `CorruptObject` instead of publishing a
record over it. Same-size byte rot after publication is not detected here; a
crash before publication merely leaves unnamed temporaries in `.incoming`, and the
objects are extracted again on the next run.
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

Requires **uv** and **Python 3.14+** (the live server compresses with the standard library's `compression.zstd`). The website has no third-party runtime dependencies.

```sh
uv run pspdb-web --catalog catalog --host 0.0.0.0 --port 8000 --store /path/to/store
```

Search input is kept in the URL as `?q=…` (for example, `/?q=EBOOT.PBP`).
Copy the address bar to share a search; opening the link restores the filter.
Clearing the search removes `q` while retaining the selected tree path.

Open **http://localhost:8000**, or the host's LAN address. Omit `--store` to hide
downloads; omit `--host` to bind only to localhost. Add `--redump /path/to/dat.zip`
(or an XML DAT) to match exact ISO SHA-1 + size against Redump, which supplies the
UMD population denominator of the coverage chrome and SerialStation's disc
mapping below. The DAT is loaded at startup; ingest records hashes without
depending on Redump.
Store availability checks have a 15-second deadline per batch. A stalled request
shows **Check failed**, not **Missing**, and does not block later batches. Reload
the page to retry failed checks after restoring access to the store.
Add `--umdatabase /path/to/pages` for exact SHA-1 links from saved UMDatabase
entry pages named `ID.html` (for example, `E39CFE68.html`).
Add `--nopaystation /path/to/snapshots` (a folder of NoPayStation TSV snapshots, or
one `.tsv`) for the PSN population denominator. Coverage totals come only from the
snapshots supplied on the command line; nothing is fetched.

Add `--serialstation /path/to/serialstation.json` for links to SerialStation's
PKG-specific `/pkgs/<UUID>/` pages. Matches require the package's SHA-1, exact
byte size, and full PSN content ID; a content-ID match alone is insufficient.
Build the snapshot by discovering PKG links on content-ID pages and checking
each candidate package's published identity:

```sh
uv run python tools/serialstation_acquire.py --catalog catalog \
  --output .work/serialstation/catalog.json
uv run pspdb-web --catalog catalog --serialstation .work/serialstation/catalog.json
```

The same `--serialstation` option works with `pspdb-web export`. Only exact
matches receive links; there is no fallback to a content-ID page. Serving and
exporting never query SerialStation. Re-running acquisition checks new package
identities only; `--refresh` rechecks the current catalog, including misses.
Version 1 content-ID-only snapshots must be rebuilt with `--refresh`; the viewer
accepts only version 2 package snapshots.

For UMDs, acquire SerialStation's PSP disc index into the same snapshot:

```sh
uv run python tools/serialstation_discs_acquire.py \
  --output .work/serialstation/catalog.json
uv run pspdb-web --catalog catalog --redump /path/to/dat.zip \
  --serialstation .work/serialstation/catalog.json
```

The listing pages map each disc UUID to its `Internal ID` and data `Version`
(`disc_serials`, keyed `AAAA-NNNNN/M.mm`); detail pages add SerialStation's
explicitly published Redump cross-references (`discs`). `--listing-only` reads
just the listing pages and keeps the prior Redump index. The viewer links each
UMD to `/discs/UUID`: first through an exact ISO SHA-1 + size Redump match and
SerialStation's published Redump ID, otherwise through the UMD's own `disc_id`
and `disc_version` (from `UMD_DATA.BIN`/`PARAM.SFO`). A serial/version key
identifies a disc build, not bytes, so it may list several label editions
(for example Original and Best); all are retained. SerialStation disc pages
carry the Redump cross-reference, so UMD rows do not link Redump directly.
Reconstructed PS1 discs inside PSN packages keep their exact Redump links.
Redump remains the UMD coverage denominator.

Disc acquisition caches validated listing and detail HTML under
`.work/serialstation/discs`; rerun to resume, or use `--refresh` to fetch again.
A failed scan merges any verified mappings, retains prior mappings, marks
`disc_index_complete` false, and exits nonzero. With no new mappings, the
snapshot is unchanged. A complete listing pass replaces `disc_serials`; a
complete detail pass replaces `discs`; package entries are preserved. Partial
indexes are usable but do not establish absence of a SerialStation page for an
unmapped disc.

Unlike the content-ID API, the package pages may require Cloudflare clearance.
Acquisition accepts `SERIALSTATION_COOKIE` and `SERIALSTATION_USER_AGENT` in its
environment for an authorized session; credentials are never written into the
snapshot. Do not put cookie values in shell history or committed files.
HTTP 403/challenges, malformed pages, and ambiguous package matches fail
acquisition rather than becoming misses. Incremental package acquisition
checkpoints every 100 resolved content IDs and keeps completed lookups when a
later request fails, so rerunning resumes; a failed `--refresh` leaves the
previous snapshot intact. Disc acquisition follows the partial-index rules above.
Matching records evidence at acquisition time, not a guarantee that an external
page remains available.

Coverage is stated inline in the tree, not on a separate page or panel: one
right-aligned chip per reference population, on the single group that population
maps onto — `umd` for Redump, `psn` for NoPayStation. It names the source and the
held share, such as `REDUMP 49.3% · 1,749/3,545`, and links to that source's own
coverage view: [Redump's PSP disc list](http://redump.org/discs/system/psp/) and
the [NoPayStation home page](https://nopaystation.com/), which draws its own
per-list coverage bars.
Clicking it neither selects nor expands the row. Hovering gives the full sentence
and, for UMD, the supplied Redump snapshot name and version. Subgroups such as
`umd/game` or `psn/patch` carry nothing: one global count per source. Omitting a
flag omits that source's chip. The full `coverage` payload (per-category and
per-list totals, unmatched local counts and local/reference kind conflicts) stays
in the API and export for analysis; the browser header shows only the total file
count.
UMD video labels use the SFO title when available, otherwise the observed disc
identifier. Missing optional SFO metadata does not prevent browsing its inventory.
The API and exported `catalog.bin.gz` keep inventories in `trees[kind][sha256]`.
Root rows use their explicit `iso`, `pkg`, `nand` or `update` inventory; nested
files use their derived extractor inventory. Inline contextual extractions retain occurrence precedence.

Both the API and the export send one binary columnar container (wire format 4,
`website/pspdb/wire.py`, which documents the exact byte layout). Directory
structure, names, sizes and hash references are varint columns; names live once in
a dictionary; every distinct SHA-256 gets one slot; identical subtrees (the same
game assets under every regional ISO) are stored once and referenced; a file size
is stored once per hash; and everything that is not tree structure (records,
coverage, tree profiles such as extractor/naming rule/staleness/errors, per-file
extras such as Redump matches, flags like `downloads_enabled`) travels as one JSON
`meta` section. The viewer reads the columns straight into typed arrays and never
builds per-occurrence objects. Full 32-byte digests are not part of the container:
it carries an 8-byte prefix per slot (the viewer shows the first 12 hex characters
of a hash from it) and the full digests are fetched lazily in chunks of 4096
slots (`slot // 4096`, byte offset `(slot % 4096) * 32`; raw concatenated digests,
the last chunk is short). Encoding fails loudly if two different digests ever share
an 8-byte prefix. Parents that a path only implied come back as ordinary directory
entries, and one name cannot describe two different children of a directory. Every
directory is stored directories-first, then by name in UTF-16 code unit order, the
order the viewer shows. On the 2026-10-30 catalog (41,458 trees, 2.73 M file rows,
1,248,854 distinct digests) the container is 42.9 MB raw, 22.7 MB with gzip-1,
21.9 MB with gzip-9 and 20.2 MB with zstd-3, against 178.6 MB raw and 78.8 MB
gzip-1 for the previous JSON encoding; the digest chunks (40.0 MB) are only fetched
for the rows a user asks about.

`GET /api/catalog` returns the container as `application/octet-stream` with
`Content-Encoding: zstd` (level 3) when the client accepts it, otherwise gzip
(level 1), otherwise identity (the highest `q` wins, zstd before gzip on a tie).
`Vary: Accept-Encoding` is always sent. Full digests come from
`GET /api/hashes/<generation>/<chunk>` (`application/octet-stream`, immutable
cache headers). `<generation>` is the `generation` string in the container's
`meta` (a digest of the full hash table); the server answers 409 for any other
generation, so a viewer holding an older catalog reloads it, and 404 for a chunk
that does not exist. Availability and download endpoints keep taking full hashes;
the viewer resolves the full hashes of the rows it needs through the chunk fetch
first.

The local server caches the container's zstd, gzip and identity bytes, the hash
table and the download index as one coherent snapshot. Requests recheck catalog paths, modification/change times,
sizes, inode identities and annotation dependencies at most once every five seconds. One background
refresh runs at a time; requests can use the previous snapshot for up to 30 seconds
after its last successful check. Cold or expired requests wait for regeneration.
Refresh errors are logged and return HTTP 500 rather than hiding failures behind
an indefinitely stale catalog. Conditional requests use encoding-specific
ETags (a digest of each representation's bytes), so unchanged reloads can return
HTTP 304 without transferring the catalog; a validator for one encoding never
validates another. Availability checks still inspect requested store objects live.

Completed, stable snapshots are also cached outside `catalog/`, under
`$XDG_CACHE_HOME/pspdb/web` (default `~/.cache/pspdb/web`). Set
`PSPDB_WEB_CACHE_DIR` to choose another directory, or to an empty string to disable
disk caching. A restart reuses the compressed snapshot (the zstd and gzip
representations plus the raw hash table) only when source signatures,
annotation mappings, download mode and viewer implementation still match. Cache
files are private, atomically replaced and checksum-checked; missing, corrupt or
unwritable caches fall back to the authoritative catalog. Invalid catalog data
still fails validation. A source change during generation prevents publishing that
generation to disk. This cache is disposable, not another catalog or database.

The live server uses zstd level 3 (0.1 s for the whole container; gzip level 1 for
clients without zstd takes 0.4 s) to keep preparation latency low; static exports
retain gzip level 9. On the 2026-10-30 catalog with downloads enabled and the
`--redump/--umdatabase/--nopaystation/--serialstation` annotations, on this Linux
workstation: a cold start prepares the first response in about 26 s (catalog scan
5.5 s, container encoding 9 s, download index 8 s, compression 0.5 s); a restart
that reuses the disk cache takes 13 s with a store (the download index is rebuilt
from the cached container) and 0.5 s without one. These measurements
exclude browser download and tree construction.

The lowest-level virtual groups start folded: `umd/game`, `umd/video`,
`umd/other`, `firmware/nand`, `firmware/update`, and the PSN categories. Their
parent groups remain expanded. Opening a category reveals source files whose
extractions still start folded; search and deep links reveal the required ancestors.

The browser reads the container straight into typed arrays (`catalog.js`) and expands
shared directories and extraction trees into an occurrence tree: parallel typed arrays
in preorder (parent, name, subtree end, size, hash slot, attached extraction, flags),
one entry per row a user can reach (7.6 M on the 2026-10-30 catalog) and no per-row
JavaScript object. A row is an integer; its path, label, extractor tags, error counters
and annotations are derived when needed, folding is one byte per row, and the visible
list skips collapsed subtrees. A Web Worker searches and sorts copies of the same arrays
(transferred, not re-interned) without blocking keyboard input. Superseded
queries are cancelled; no results are dropped or capped. Only viewport rows are
mounted, and the DOM scroll height stays below browser layout limits. Wheel,
native touch/momentum, and page-scrolling keys move one logical pixel per native
scroll pixel, regardless of the result count. A bounded native-input window is
rebased near its physical edges when more results remain. After scrolling settles
(never while a finger is down), the scrollbar returns to global coordinates
without moving the visible rows; dragging it and using End still reach the final
row. Short unscaled margins at the scrollbar's ends leave room for overscan; the
rest maps proportionally across the remaining results. The thumb can change
position during these remaps, but browser touch physics, pinch zoom, and horizontal
scrolling remain native. Search covers files inside collapsed branches;
narrowing a query reuses matches and checks only the surviving candidates' strings,
memoizing repeated lookups and skipping already-satisfied terms. Broadening searches
the full index.
Hash terms are 8–64 hexadecimal characters (case-insensitive) matched as **prefixes**
of a file's own SHA-256: not hashes inherited from parent containers, and no longer
anywhere inside the digest (a mid-hash fragment such as `06fdaefe3c62` finds
nothing). Terms up to 16 digits are compared locally with the 8-byte prefixes in the
catalog. A longer term matches its first 16 digits locally, then checks the remaining
digits against the full digests of the (few) candidate slots, fetched in 128 KiB
chunks; if that fetch fails the search status says so and search stays usable, and a
409 (the server holds a newer catalog) reloads the page. Shorter hex strings are
ordinary text and match names, labels, metadata and errors, never hashes. A catalog
record's name carries its full SHA-256, so a text search still finds it by any part of
its hash. Matching occurrences remain separate; ordinary text and filename searches
include ancestor context.
The same worker and `catalog.js` are included in static exports; serve them over HTTP as below.

On narrow screens, the viewer prioritizes names and sizes, shows search-result
filenames instead of long ancestor paths, and keeps the full selected path, exact
byte count, and extraction details below the tree. **Copy SHA-256** replaces the
narrow-screen hash column; **Open in tree** opens a search result without a double
tap. Touch rows are 41 pixels high (desktop rows remain 21 pixels), with stronger
16-pixel indentation on narrow screens, continuing at 8 pixels for deeper levels
instead of flattening them, and aligned file/folder markers. Virtual
scrolling follows the actual row height. Toolbar controls retain their larger
touch targets. Desktop columns and keyboard navigation remain available; selecting
an error reveals its full message on either layout.

The search field is editable before the catalog arrives and throughout index
preparation. The latest entered query runs automatically once ready, without
stealing focus from the field. Clearing a pending query is safe, and a catalog
download failure preserves the entered text.

The hash column shows the first 12 hex digits, taken from the prefix. Copying a hash
(the row button or **Copy SHA-256**), a **Download** link and a store check resolve
the row's full digest through its chunk first (one request per chunk, cached, and
checked against the catalog's prefixes before use); the availability and download
endpoints still take full hashes. Hovering a hash prefetches its chunk, so the click
copies at once.

Measured on the 2026-10-30 catalog (7,601,835 rows, 7,367,003 files; 20.2 MB on the
wire with zstd, 42.9 MB decoded) in Chromium 150 on this Linux workstation against a
local server: the tree is browsable 1.1 s after navigation (1.2 s with the search index
ready), against 7.7 s (15.8 s) for the previous viewer fed the 78.8 MB JSON by the same
browser. After a garbage collection the page holds a 34 MB JS heap plus 249 MB of typed
arrays (previous viewer: 1.06 GB after collection, 1.62 GB before); the whole renderer
process, worker included, is about 0.87 GB, against 1.93 GB before. Searching the
whole catalog, installing the results and rendering them took 110–180 ms for `eboot.bin`
(62,261 files) and 120–130 ms for `psp_game` (7,128,068 files, 7,349,188 rows counting
folders); typing a 12-digit hash takes under 80 ms and refining it a few ms. The page
fetches digest chunks only for rows a user touches, 128 KiB each, instead of the 40 MB
table. These are local measurements, not latency guarantees.

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
  --umdatabase /path/to/umdatabase/pages \
  --nopaystation /path/to/nopaystation/snapshots
uv run --locked python -m http.server --directory dist 8001
```

Open `http://localhost:8001/site/`. The output directory must be empty. Supply the
reference inputs on **every publication**: export does not discover or fetch them
automatically, and omitting a flag omits that source's UMD associations. Redump
matches require exact SHA-1 and size; UMDatabase matches require exact disc SHA-1.
Coverage totals come only from the supplied snapshots: `--redump` provides the UMD
denominator alongside its exact ISO links, `--nopaystation` the PSN denominator, and
omitting one omits that source's inline group chips. Bundled PSX Redump associations are
included separately. Export leaves ingested records unchanged and publishes only
browser assets and metadata; Store/downloads are disabled. Relative asset URLs
support repository paths such as `/pspdb/`.

Static exports contain the container as `catalog.bin.gz` (gzip level 9, about 22 MB
on the current catalog) plus the full digests as `hashes/<chunk>.bin` files of at
most 4096 digests (128 KiB) each beside it, keeping every file far below GitHub's
100 MiB per-file limit. The viewer decompresses the catalog with the browser's
native `DecompressionStream('gzip')` and fetches `hashes/<chunk>.bin` on demand.
`index.html` declares both locations (`data-catalog`, `data-hashes`); the live
server uses `api/catalog` and `api/hashes/<generation>/<chunk>`. Serve
`catalog.bin.gz` as gzip data (for example, `application/gzip`), not as an
already HTTP-decoded response. Python's static server and GitHub Pages serve it
this way without additional configuration. The hash chunks carry no generation in
their path: replace them together with the catalog, and the viewer checks every
fetched digest against the catalog's 8-byte prefixes so a stale cached chunk is
detected rather than trusted.

While loading, the viewer shows download progress and received bytes, with a
percentage when the response provides a usable length. Unknown-length or
HTTP-decoded responses use an indeterminate bar instead of an inaccurate
percentage. After transfer, the status changes to “Preparing catalog…” until
the tree is ready; failed transfers show an error rather than a completed bar.

Keep source code on `main` and exported snapshots at the root of a separate
`pages` branch (`index.html`, assets, `catalog.bin.gz` and `hashes/`, without a `site/` wrapper).
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
# The viewer tests encode their fixtures with the real Python encoder, so run them
# inside the uv environment (python3 on PATH must be 3.14+).
uv run --locked node website/tests/tree-catalog.mjs
uv run --locked node website/tests/catalog-oracle.mjs
```

`tree-catalog.mjs` drives `catalog.js`, `app.js` and the search worker in a stubbed
DOM; every fixture must also match, row by row, the object-per-row tree the viewer
used before the typed-array occurrence tree (`reference-tree.mjs`, a test-only
oracle). `catalog-oracle.mjs` repeats that comparison on the checked-in fixture and,
with `PSPDB_ORACLE_DATA` (a JSON dump of the data dict) and `PSPDB_ORACLE_CONTAINER`
(a directory with `catalog.bin` and `hashes/`), on a whole catalog under
`node --max-old-space-size=12000` (7.6 M rows in about 25 s). `browser-tree.mjs`
needs a running site and Chromium with `--remote-debugging-port=9333`; it exercises
folding, search, sorting, downloads, copy, deep links, narrow screens and stale
catalogs in the real page (`PSPDB_BROWSER_QUICK=1` skips its exhaustive first sweep).

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
temporary files. PSPDB imports the SDK source directly. Extractors work on retained
input buffers, not by reopening CAS objects.
Zig hashes their outputs and queues
nested extraction using retained buffers; `--store` additionally persists those bytes.
No extractor uses scratch directories or `TMPDIR`.
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
Native source normalization and patch lists for make-npdata and pkg2zip live in `ingest/build.zig`;
`tools/prepare_native.py` applies the shared preparation steps without mutating
the fetched dependencies. Standalone builders explicitly opt into patching
their already isolated temporary source directory.

PSAR revision 4 runs the Zig-PSP ports of the pspdecrypt algorithms through a native memory
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

The decoders are pure-Zig ports of pspdecrypt commit `c156627db7634d395c380c0a9589130f603307fc`
in Zig-PSP, with shared PRX recipes and bounded per-call IPL state. DES-CBC is
implemented in the crypto module; KIRK state is call-local. The former custom
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
temporary extraction directories. DOCUMENT is native too; the only remaining Python in
the ingest is the `--skip-existing` freshness scan.

PRX and KL3E/KL4E decode in memory through Zig-PSP's pure-Zig ports of pspdecrypt
(`tools/prxencrypt`, GPL-3.0). They need no external helper, NAS input reread, or
temporary output files. This links GPLv3 Zig-PSP code into the ingest binary.
PRX revision 12 supports `~PSP` modules and `PSPsysGP` firmware resources,
with layouts 0/1/2/4/5/6; legacy layout 8 shares the layout-0 algorithm.
Coverage includes standard update XOR recipes and Go firmware index keys.
Coverage includes the 6.36 user-module tag `0x457B8AF0` (type 6). The console-bound CMD8 signcheck path is entered only when the scrambled size field at `0xB0` is invalid; other decrypt failures surface as themselves.
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
decryption and disc reconstruction use the native contextual decoders (see
[PS1 Classics (PSX)](#ps1-classics-psx)).

NPD EDAT files are authenticated and decrypted in memory by the native ingester.
The Zig build links pinned make-npdata commit
`5f44642fa24331da79f4bae6bea516f1784cf1c5`, with private-buffer and thread-safe
AES-table patches. Its GPLv3 crypto code is linked into the executable.
No EDAT subprocess, input reread, temporary plaintext file or `PSPDB_EDAT` helper is used.

### EDAT keys derived from the package

License-2 EDATs of a PSN package are decoded with a key taken **from the package itself**,
not from a RAP file. Before the package walk (EDAT entries may precede `EBOOT.PBP` in the
package table, so order is irrelevant) ingest decrypts only the PBP header and the first
bytes of `USRDIR/CONTENT/EBOOT.PBP`'s `DATA.PSAR`, never the game payload, and
recovers the PSP version key `V` with libkirk's `bbmac_getkey` from the protected header's
own MAC: the NPUMDIMG header (MAC at 0xC0; PSP games, minis, PC Engine, NeoGeo) or the PS1
Classic PGD (`PSISOIMG0000` PGD at +0x400, `PSTITLEIMG000000` PGD at +0x200; MAC at 0x70,
header MAC verified against the DNAS key first). The EDAT key is then
`X = AES-128-ECB-DECRYPT(key_357C[(type-1)*16 ..][0..16], V)` with `type` the NPUMDIMG
version byte (2 or 3) or 1 for a PGD and `key_357C` the public table of libkirk
`sceNpDrmGetFixedKey`; `X` is what `rap2rif(RAP)` yields, and the RAP is its exact inverse
(`rif2rap`, verified against make-npdata's `rap_to_klicensee`). An NPUMDIMG header carries no
independent authentication, so `X` is a candidate that the EDAT's own keyed MACs confirm
(they always decide). Only packages with an `EBOOT.PBP` can be derived; DLC packages and
PS3-native content cannot.

Precedence per EDAT, by its NPD content ID:

1. the key derived from a package whose content ID equals it (provenance option `key:derived-eboot`);
2. otherwise a regular, nonsymlink, exactly 16-byte `<NPD-content-id>.rap` from the shared license
   directory (`PSPDB_RAP_DIR`, else `XDG_DATA_HOME` or `~/.local/share/pspdb/licenses`;
   option `key:rap-file`). A RAP file is **never** consulted when a derived key exists, so a
   stale or wrong file for a derivable package is ignored, not trusted and not an error;
3. otherwise empty licence markers are published as before (`unlicensed-marker`).

Missing/invalid keys and failed authentication produce an EDAT extraction error, without
rejecting the parent inventory or publishing plaintext. Key bytes never enter catalog JSON
or provenance or any log.

EDAT results stay **global**, keyed by the EDAT's SHA-256 alone, not contextual like
DOCUMENT/DOCINFO or PC Engine/PSP-KEY: the MAC-authenticated plaintext is a pure function
of the EDAT bytes whichever key opened it, so there is no sibling dependency to record.
The `key:` option only says which key source opened it in the run that extracted it;
a later run with no key reuses the stored result as before.

EDAT revision 7 adds the package-derived key and the `key:derived-eboot` / `key:rap-file`
provenance options; results of earlier revisions are not reused.

EDAT revision 3 also recognizes the authenticated empty `ISO.BIN.EDAT` markers
shipped beside `PBOOT.PBP` in PSP update packages. These NPD v2/license-3/flags-0x0c
files use an all-zero developer klicensee, require no RAP, and decrypt to an empty
payload. Their keyed filename, content-ID, developer, metadata and header fields
still authenticate; arbitrary license-3 payloads remain unsupported.

EDAT revision 5 also accepts empty license-2 markers (`ISO.BIN.EDAT` and DLC
`.EDAT` beside `EBOOT.PBP`) when their RAP is unavailable. They declare a zero-length
payload, so no ciphertext is skipped. Their RIF-keyed header MAC cannot be checked
without the buyer's license, so instead their header `dev_hash` must authenticate
under a public klicensee (all-zero, PSX, or PSP key 1/2). They publish an empty
`payload.dat`, with provenance option `unlicensed-marker`. A derived key or present RAP is
still tried first and fully authenticates the marker (no `unlicensed-marker` then); markers
with a payload still require a key.

EDAT revision 6 adds the SDAT and interleaved layouts of PlayStation Store packages. It
supports license-2 NPD v1/flags-0 and v2/flags-0-or-0x0c files, v3 license-2 flags-0x3c
files (`PS3-KEY.EDAT`, `ISO.BIN.EDAT`, `MINIS.EDAT`: HMAC block hashes with the 0x20-byte
metadata ahead of the data; only the observed single-block form, so a payload of up to
16 KiB), and SDAT (NPD v2/v3, license 0, flags `0x0100000D` = SDAT | encrypted block keys |
compressed, no content ID). SDAT needs no RAP: its key is the fixed public SDAT key XOR the
header's dev_hash, its blocks are raw or LZ-range-coded (upstream make-npdata `lz.c`, patched
to bounds-check input and output, run only after the block's MAC passed), and the result
must be exactly the declared length. Because that key is public, SDAT MACs prove integrity
and self-consistency, not origin. All files use 16 KiB blocks and at most 64 MiB
plaintext. Keyed header, metadata-table and every ciphertext-block MAC must pass before publication.
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


### PS1 Classics (PSX)

PS1 PKG ingest uses Zig-PSP for PBP/SFO parsing and a native, in-memory Zig
pipeline (`ingest/src/psx/`, provenance `pspdb-psx` revision 4, options
`in-memory`) to rebuild the discs, attached beneath the original `DATA.BIN`
occurrence; PBP revision 6 records that changed contextual provenance (revision 5
results stay immutable). There is no helper, scratch directory or environment variable. The
pipeline reproduces the former PSXtract-2 revision 3 output byte for byte:
`DATA.PSAR` (`PSISOIMG0000` single or `PSTITLEIMG0000` multi disc) is parsed, each
disc's data blocks are LZ-decoded into the data track, its sectors are regenerated
(sync, BCD MSF from 00:02:00, EDC/ECC; form 2 EDC inferred from the boot sectors),
and the ATRAC3 CDDA tracks are unscrambled, decoded and laid out after the data
track with their pregaps. Each disc is one raw 2352-byte-sector image. Children of
`DATA.BIN`: `disc.bin` (or `disc-1.bin`…`disc-N.bin` in disc-index order) plus the
non-empty `ISO_HEADER.BIN` (`ISO_HEADER_<n>.BIN` for multi-disc), `ISO_MAP.BIN`,
`STARTDAT.BIN`, `SPECIAL_DATA.BIN`, `TRASH.BIN` and `OVERDUMP.BIN`. As before,
`TRASH.BIN` keeps the last non-empty trash prefix seen and `OVERDUMP.BIN` is the
last disc's. CUE files are not produced. A disc must be a non-zero multiple of 2352
bytes with an ISO9660 descriptor in sector 16, or the whole `DATA.BIN` extraction
fails.

Deliberate differences from PSXtract-2 revision 3:

1. An ambiguous prebaked CUE (several `-N` variants for one serial) is resolved by
   the unique candidate whose `REM MD5` equals the rebuilt data track; otherwise the
   extraction fails with `AmbiguousPsxCue` (fixes Jet Moto 2 without guessing).
2. Output names never depend on CUE titles (fixes the Osaka disc-name collision).
3. An auxiliary block without an in-block zero terminator is entirely `TRASH.BIN`
   and adds nothing to `OVERDUMP.BIN` (fixes Constructor and Space Griffon); the
   data track is unaffected.
4. Every PGD verifies its header MAC, table MAC and every block MAC before any
   plaintext is used (PSXtract skipped block MACs).

The CUE database (`ingest/src/psx/cue_db.bin`, 10,345 serials) is generated from the
prebaked `cue/` directory of PSXtract-2 commit
`4691fc405698d53927df6e4f59c3e9b113c13706` by `tools/psx_cue_db.py`; it supplies
only the single-disc pregap/length overrides and the MD5 for change 1. Regenerate
with `python3 tools/psx_cue_db.py` and verify the committed blob with
`python3 tools/psx_cue_db.py --check`. The Redump MD5 is not computed or recorded;
mismatches were never an error.

ATRAC3 audio is decoded by a trimmed FFmpeg ATRAC3 derivative
(`ingest/src/psx/atrac3/`, see its `NOTICE`) whose arithmetic reproduces the Sony
ACM decoder bit for bit (verified over a whole Vib-Ribbon track), including the
WAV offset-44 quirk of PSXtract's WAV-to-BIN step. That exactness depends on x87
80-bit `long double` and volatile binary32 stores, so PSX extraction is x86-64
only and the C file must never be built with fast-math or FP contraction.

Each conversion holds the decrypted PSAR views, the data track and every decoded
audio track in memory (hundreds of MB per disc); at most two PSX conversions run
at once process-wide, whatever `--threads` is.

DOCUMENT, like PSX, needs no external process, `/proc/self/fd` or scratch space.

Standard VMP memory-card wrappers expose their unchanged 131072-byte raw card as
an `.mcr` child. This follows the
[upstream wrapper layout](https://github.com/sahlberg/pop-fe/blob/d74e4ab44eedbf41abd759a8db7cd091779dea82/vmp.py):
131200 total bytes, `00 50 4d 56` magic and a 128-byte header. This is byte
extraction, not signature verification or per-save filesystem interpretation.
VMP extraction preserves the original wrapper.

### DOCUMENT manuals

Fixed-key PS1/PSP manuals and explicitly paired PSP manuals decode in memory
through Zig-PSP's `tools/prxencrypt/document.zig` (a port of the pinned
[PSP-DOCUMENT.DAT reader](https://github.com/seiya-dev/PSP-DOCUMENT.DAT/tree/8c95b37949c9a9ca183b7fd69c85d2e2dad7216d))
driven by `ingest/src/document.zig`, provenance `pspdb-document` revision 5, options
`in-memory`. There is no helper, environment variable, scratch directory or Python
dependency. The extractor borrows the source and companion bytes and emits each page
PNG (and the `psp`/`ps3` directories) straight into the inventory. Any decoder error is
a non-fatal `ExtractionFailed` on the DOCUMENT extraction; allocation failure stays
fatal. It was verified identical to the former Python helper on all 2,274 recorded
catalog DOCUMENT extractions, except that Pillow's PNG check became the structural
check below.

DOCUMENT revision 3 recorded the byte-input/callback implementation separately
from earlier revision 2 helper provenance (`PSP-DOCUMENT.DAT`); revision 4 adds
999-slot tables, distinct PS1 PS3-only frames, 320-byte companions, zero-page manuals
and the 128 MiB cap described below; revision 5 moves extraction to the native
extractor with the new provenance and structural PNG validator. Earlier DOCUMENT
results keep their `PSP-DOCUMENT.DAT` provenance and are still understood; new
results are written into new `v5` pairs and containers embedding DOCUMENT results
become stale. ISO/PKG revision 4 and nested ISO9660 revision 3 provide namespaces
for inventories embedding paired manual results. Keep historical records intact:
different provenance/options must not overwrite successful results at the same
revision. Rebuild the ingester after updating `tools/extractor_versions.json`.
The first run at these new revisions reprocesses affected source kinds even with
`--skip-existing`; it adds new pairs without replacing the older revisions.

Fixed-key recognition uses the encrypted DOC magic/version block, not filenames
or generic PGD magic. The reader checks supported header/table/page protection;
these are source-consistency checks, not independent trusted-origin authentication.
Extraction preserves the wrapper and exact PNG bytes. Neutral `psp/001.png` and
`ps3/001.png` paths retain each platform's page ordinals, including shared frames.
Only page PNGs are published; no source/page map is generated.

All expected pages must pass a structural PNG check (signature, chunk CRCs, IHDR
pixel budget, a single trailing IEND) before any page is emitted. The check replaces
the former Pillow validation and does not decode pixels. A late-page failure emits
nothing and records an extraction error in the parent inventory. No whole-disc
reconstruction or inferred PBP key is used.
Support covers the 99-slot (header code 0) and 999-slot (code 1) families. PSP
manuals require PS3 frames identical to the PSP frames; PS1 manuals may also carry
PS3 frames distinct from the PSP ones, which are decoded, authenticated and
published as their own `ps3/NNN.png` files (shared frames stay one decode with a
link). Generic PGD remains unsupported. A structurally valid, fully authenticated
manual with zero pages succeeds with an empty extraction (no page files, no error).
A frame whose authenticated PNG is itself truncated (an authoring defect) stays an
error and publishes nothing.
Resource limits are 128 MiB input (`max_source` in `ingest/src/document.zig`,
`max_document_size` in the ingester), 256 MiB total page frames, 4096 encrypted-range
descriptors per page and 16 Mi pixels per image.

For non-default PSP manuals, PKG, ISO and nested ISO9660 inventories bind an
unrecognized legacy-PGD `DOCUMENT.DAT` to its exact same-directory `DOCINFO.EDAT`.
The companion must match the exercised 304-byte/eight-byte-key layout and pass
outer signature, inner header, MAC-table and complete ciphertext-block checks,
including padding. Like upstream, a 320-byte companion is also accepted: its final
16 bytes are unauthenticated trailing data that never feed the signature, MACs or
key, and only the first 304 bytes must verify. Any other length, or an unsupported
or damaged present companion, fails the root (`InvalidDocinfo` for a bad length);
without a companion the unrecognized wrapper remains opaque. Other generic
PSPEDAT/PGD extraction remains unsupported except the fixed-key `PSP-KEY.EDAT` described
below; the separate NPD EDAT extractor above does not handle those wrappers. The recorded dependency size is the companion's
actual size (304 or 320).

Paired results are inline on the original DOCUMENT occurrence, never globally
cached by its hash alone. `dependencies` records the companion's path relative to
that immediate inventory, SHA-256 and size. Reuse validates the same sibling
binding; provenance changes invalidate the containing result. Titles are not key
inputs. The extractor never discovers a companion from the input filename.

DOCUMENT extraction publishes only page images; there is no source/page map and no
`structure.json` child. This also applies to inline manual inventories.

### PC Engine Archives

PlayStation Store "PC Engine Archives" (TurboGrafx) packages hold a PSP emulator
plus two obfuscated containers and a key:

| File | Layer | Authentication |
| --- | --- | --- |
| `USRDIR/CONTENT/PSP-KEY.EDAT` | `\0PSPEDAT` header + fixed-key PGD (drm_type 1) with a 16-byte payload | PGD header, table and block MACs; the version key is recovered from the file itself (PPSSPP libkirk logic), so **no RAP is needed** |
| `USRDIR/CONTENT/CONTENT.DAT` | XOR stream over a container | none intrinsic: bad-magic and structure checks only |
| `USRDIR/DOC/CONTENT1.sdat` | SDAT (see EDAT revision 6) over the same XOR stream | SDAT header, metadata and every block MAC (public key: integrity, not origin) |

`PSP-KEY.EDAT` is detected by its `\0PSPEDAT` signature and extracted as kind `pspedat`
(revision 1; `payload.dat`, displayed with the source stem). Its 16-byte payload is the
content key and is published like any other payload, including `PS3-KEY.EDAT`'s.
The 0x40-0x8f digest fields and the optional 16 trailing bytes of 336-byte files are
shape-checked only.

The XOR layer is `plain[i] = data[i] ^ key[i & 15] ^ PUB[i & 511]`, where `PUB` is the
fixed 512-byte table of qwikrazor87's PCE_py_tool (`keys/public.key`, SHA-256
`b2d7084c...7165`, embedded in `ingest/src/pce.zig` and pinned by a test). The container
has a 0x80-byte header (magic `12 34 56 78`, little-endian entry count at 0x28) and 0x50-byte
entries (`name[0x40]`, LE offset, LE size, 8 zero bytes). It is rejected, publishing nothing,
for a bad magic, an empty table or a count above 4096, a table or payload outside the
buffer, payloads inside the table or overlapping, names that are empty, `.`/`..`, non-ASCII,
containing `/`, `\`, `:` or whitespace, lacking NUL padding or duplicated (also by case), and
nonzero entry trailers. A wrong key surfaces as a magic mismatch.

Both containers are *contextual* (`pce`, extractor `pspdb-pce`): they live inline on the
`CONTENT.DAT` / `CONTENT1.sdat` occurrence, key-bound by `dependencies` (path, SHA-256 and
size of the sibling `USRDIR/CONTENT/PSP-KEY.EDAT`, like `DOCUMENT.DAT` and `DOCINFO.EDAT`),
never by filename alone and never by the hash of the container. Without the key file the
containers stay opaque; an SDAT then falls back to the generic EDAT result. A tampered SDAT
(`EdatAuthenticationFailed`) or any container error leaves an empty inline tree with the
error. Members keep their original names and case (`ps3_001.png`, `N43800PL.PCE`,
`HCD2025.hcd`, ...). The single static provenance record states each trust level:
`content-dat:structure-checked`, `content1-sdat:mac-verified`; origin authenticity is
never claimed and no key bytes appear in any record. Container limit: 256 MiB.

A `*.hcd` member is the CD-ROM² TOC (`trackNN,audio|code ,<file>,<LBA>,<sectors>`). It
must parse completely and name only existing members, else the container is rejected. Every
`code` track's `*_NN.bin` is a Sony data-track container (`u32 n; n * {u32 offset, u32 size};
n independent zlib streams`) and gets a contextual child (`pcecd`, extractor `pspdb-pcecd`,
`dependencies` = the `.hcd`): the 2048-byte-sector image `disc.iso` (name rule `source_stem`,
so it is shown as `<bin stem>.iso`). The image is a cooked 2048-byte user-data sector image (`.iso` is only the conventional
extension). Most PC Engine CD tracks have **no file system**: of the 17 decoded retail
tracks, none has an ISO9660 volume descriptor, so they stay plain files. Only an image with
`CD001` at sector 16 is also offered to the nested ISO9660 extractor. It is published only if the TOC fixes its size
(`sectors * 2048`, at most 1 GiB), the stream count matches, every stream inflates completely
to 0x40000 bytes (the last one to the remainder) with no input left, streams tile the file in
order, and, on the first `code` track, sector 1 carries `PC Engine CD-ROM SYSTEM` at image
offset 2080. Objects above the store cap remain tree-only. Audio (`.at3`), GIM, PSM and ROM
members stay opaque. Not covered: PSP-side emulator internals.

Revisions: `edat` 6, new `pspedat` 1, `pce` 1, `pcecd` 1, `pkg` 8 (new inline subtrees).
