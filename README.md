# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extracted source hash owns its
inventory; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. `catalog/` contains versioned metadata and inventories contributed through PRs.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.16.0** and **libarchive** development headers/library.

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store
```

Discovers ISO files and ISO members in ZIP archives. A root `UMD_DATA.BIN` is
required. `--store` is optional. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips current
ISO results when `--catalog` is set; it is **off by default**. Bump the affected extractor revision when extraction behavior changes.

Filesystem discovery stays parallel, but only one ISO is admitted through hashing,
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

Metadata is read independently before file inventory/storage: `UMD_DATA.BIN`
and both game/video `PARAM.SFO` paths. When both SFOs exist, game metadata takes
precedence. If neither exists, the updater SFO supplies the title and version; its generic
ID does not replace the disc identifier.

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
to report affected ISO roots. Missing tools are reported as unavailable, never current.
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

The ingest CLI tests build the current executable and generate their own ISO/ZIP fixtures.

```sh
(cd ingest && zig build test)
uv sync --locked
uv run --locked python -m unittest discover -s ingest/tests
uv run --locked python -m unittest discover -s website/tests
uv run --locked python -m unittest discover -s tools/tests
node website/tests/tree-catalog.mjs
```

## Extractors

PSAR, RCO, PRX/~PSP, SCE, PBP, gzip, KL3E and KL4E processing runs automatically during
ISO/ZIP ingest when both catalog and store are set:

```sh
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store
```

Detection uses signatures, independent of filenames. SCE and PBP readers borrow
slices directly. External tools extract into Zig-owned temporary directories;
Zig hashes/stores the output and queues nested extraction using retained buffers.
Temporary directories are removed after their immediate walk; children continue from
memory. An ISO is reported complete only after all its extraction jobs succeed.

Install `pspdecrypt` and the patched `rcomage` on PATH (overrides: `PSPDECRYPT`,
`RCOMAGE`). RCOMage loads INI files from `../share/rcomage` relative to its binary
(override: `RCOMAGE_DATA`). The Linux/LZR patch is in
`tools/patches/rcomage-lzr-linux.patch`.
Python adapters run through uv and are embedded in the ingest binary.

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
