# Contributing catalog entries

Catalog metadata and inventories are tracked in Git. Fork the repository, ingest
your sources locally, and open a pull request containing new result pairs.
Source images, archives, extracted file contents, and object stores stay local.

## Generate a contribution

Install the [build requirements and extractors](README.md#build-and-ingest), then
run from the repository root:

```sh
uv sync --locked
(cd ingest && zig build -Doptimize=ReleaseSafe)
uv run --locked ./ingest/zig-out/bin/pspdb-ingest /path/to/inputs \
  --catalog .work/contribution --store /path/to/store
```

Use a fresh staging catalog for each contribution. Include the store option to
produce nested extraction trees. This command writes metadata and hashes to the
staging catalog; extracted bytes go only to your local object store.
For supported manuals, PSMFs and raw MPEG2-PS streams, configure the
[DOCUMENT helper](README.md#legacy-document-manuals),
[PSMF helper](README.md#psmf-raw-stream-traversal) and
[MPEG2-PS helper](README.md#raw-mpeg2-program-stream-ranges) before ingestion and
freshness checks. Missing helpers are not successful extraction.

The MPEG2-PS helper supports standalone extraction and automatic `mpegps/v2`
catalog pairs. Set `PSPDB_MPEGPS`, not `PSPDB_PSMF`; the default PSMF behavior is
unchanged. Its strict supported subset and ingestion budgets are documented in
the link above. A malformed or unsupported recognized stream, missing helper or
verification failure rejects the containing root. Opaque private/PES bytes and
packet spans do not establish codec or multichannel validity. Keep source files,
manifest contents and extracted bytes local; contribute only metadata/tree pairs.

Copy **new pairs** into the same relative locations under `catalog/`, preserving
existing files. For example:

```text
catalog/iso/v11/<source-sha256>-ingest.json
catalog/iso/v11/<source-sha256>-tree.json
```

PKG inputs use `catalog/pkg/v14/<source-sha256>-ingest.json` and the adjacent
`-tree.json`; the website shows them under `psn/`.

Include new nested pairs too, such as `prx/v3/`, `gzip/v2/`, `psmf/v1/` and `mpegps/v2/`.
Licensed NPD EDAT extraction also produces `edat/v2/` pairs containing decrypted DAT payloads.
Keep RAP files and all decrypted byte objects local; submit only catalog JSON.
A source already present at that revision does not need another contribution.
If your generated inventory differs from an existing inventory at the same
revision, report the discrepancy instead of replacing it. Tool executable hashes
can differ between builds; retain the provenance emitted by your own ingestion
for newly contributed records.
Paired manual outputs stay inline in their containing inventory, with exact
same-inventory companion dependencies. Do not publish them as standalone
DOCUMENT records keyed only by the manual hash.

## Validate and submit

```sh
uv run --locked python tools/validate_catalog.py
# Compare against the main branch after staging your new files:
git add catalog/
uv run --locked python tools/validate_catalog.py --base origin/main
uv run --locked pspdb-web export --catalog catalog --output dist/contribution-preview
git diff --cached --stat
```

Commit the new pairs and open a PR against `main`. Describe the releases/serials
and versions added, the ingester commit used, external tool versions/builds,
and any extraction errors or unusual results. Keep local source paths out of the
PR description. Whole-image hashes in the ingest records identify the sources.

PR checks validate the JSON schemas, filenames, source identity and size
consistency, paired records, extractor revisions, and tree paths. They also
reject edits, renames, or deletions of existing catalog records. These checks
validate catalog consistency; they cannot verify file contents without the
original sources. CI does not need those sources or the extraction tools.

Extractor fixes belong in a new revision: update
[tools/extractor_versions.json](tools/extractor_versions.json), rebuild, and add
results under the new `vN` folder. Keep historical results intact. The website
selects the newest complete pair for each extractor kind and source hash.

## Initial catalog

The initial tracked catalog contains the previously published 47-ISO snapshot:
1,084 metadata/tree pairs. Its metadata, inventories, executable hashes, and
options were preserved when moving to versioned adjacent pairs. All extractors
start at revision 1 in this tracked baseline, including PRX and gzip, which had
higher internal revision labels before the reset. This was a layout/provenance-label
migration, not a new extraction run. Future extractor changes increment from this
baseline and retain previous results.
