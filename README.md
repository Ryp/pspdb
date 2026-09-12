# pspdb

A catalog of PSP file paths, byte sizes, and SHA-256 hashes. Each extracted source hash owns its
inventory; optional file contents live in a separate deduplicated object store.

- `ingest/`: Zig ISO/ZIP ingester and ingest tests.
- `website/`: Python server, browser assets, and website tests.
- `schemas/`: shared catalog format. Generated `catalog/` stays at the root.

Run the following commands from the repository root.

## Build and ingest

Requires **Zig 0.16.0** and **libarchive** development headers/library.

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
./ingest/zig-out/bin/pspdb-ingest /path/to/inputs --catalog catalog --store /path/to/store
```

Discovers ISO files and ISO members in ZIP archives. A root `UMD_DATA.BIN` is
required. `--store` is optional. `--threads N` caps threads (default: logical CPU
count); `--no-progress` disables terminal progress. `--skip-existing` skips known
ISO hashes when `--catalog` is set; it is **off by default**. Rebuild catalogs
from source inputs after incompatible format changes.

Filesystem discovery stays parallel, but only one ISO is admitted through hashing,
metadata parsing, and its immediate file walk at a time. Nested extractors share
the worker pool and retain their input bytes in memory; they can overlap the next ISO.

Metadata is written to `catalog/<extractor>/<hash>.json`,
with the directory identifying the extractor. Every extractor writes its output
inventory to `catalog/trees/<source-hash>.json` using the same
[tree schema](schemas/tree.schema.json). Different ISO hashes retain separate trees,
even with identical entries. See the [metadata schema](schemas/record.schema.json).
Inputs are read-only. Generated
catalogs, object stores, and source images should not be committed.

Metadata is read independently before file inventory/storage: `UMD_DATA.BIN`
and both game/video `PARAM.SFO` paths. When both SFOs exist, game metadata takes
precedence. If neither exists, the updater SFO supplies the title and version; its generic
ID does not replace the disc identifier.

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
`--skip-existing` skips nested processing along with the parent ISO. The thread
cap applies to ingest itself; external tools run in child processes.

KL decoding uses `pspdecrypt-kle` on PATH (`PSPDECRYPT_KLE` override): build
pspdecrypt with `tools/patches/pspdecrypt-kle.patch` and install that binary under
this separate name. The patch exposes standalone streams and adds decoder bounds
checks; it rejects outputs exceeding 64 MiB.
