# PSPDB coverage panel + PKG kind classification

## Context

Two asks, one change set:

1. Make it visible how much of the *released* PSP population PSPDB actually holds: local ISO records versus the Redump PSP disc population, and local PKG records versus the NoPayStation (NPS) PSN package population. Surface **in the website only** (user decision: no new CLI tool).
2. Make PKG content classification real: decide from PKG/SFO facts whether a package is a game, demo, DLC, patch, theme, PS1 classic, minis, or NeoGeo, instead of today's `content_type`/`package_flags` guesswork in `app.js`.

Counting unit is **artifacts only** (discs and packages). No title/serial-level rollup.

End state: `pspdb-web` (serve and export) accepts `--nopaystation`, computes a `coverage` payload field, records a `psn_kind` on every PKG record, and the browser gets a second top-level view (`Coverage`) beside the existing tree. PKG ingest retains the SFO categories the classifier needs (new `pkg` revision 6, local PKGs re-ingested).

### Measured ground truth (established this session; do not re-derive, but verify at the end)

101 local PKGs live at `/mnt/nas/dev/pspdb-pkgs/completed/<sha256>-<size>.pkg`; all 101 content IDs appear in NPS lists. Decrypting them shows exactly one boot PBP per package under `USRDIR/CONTENT/`:

| boot entry | inner PBP `PARAM.SFO` `CATEGORY` | NPS list | count |
| --- | --- | --- | ---: |
| `USRDIR/CONTENT/PBOOT.PBP` | `PG` | `PSP_UPDATES` | 67 |
| `USRDIR/CONTENT/EBOOT.PBP` | `ME` | `PSX_GAMES` | 13 |
| `USRDIR/CONTENT/EBOOT.PBP` | `EG` | `PSP_GAMES` (incl. minis 5, NeoGeo 1) | 13 |
| `USRDIR/CONTENT/EBOOT.PBP` | `MG` | `PSP_DEMOS` | 3 |
| `USRDIR/CONTENT/PARAM.PBP` (no EBOOT) | `MG` | `PSP_DLCS` | 2 |
| none (`*.PTF`, no root `PARAM.SFO`) | — | `PSP_THEMES` | 3 |

Outer (root) `PARAM.SFO` `CATEGORY` only mirrors `content_type`: `PP` (PSP), `1P` (PS1), `MN` (minis), `HG` (NeoGeo), absent (theme). It is **not** a demo/DLC/patch discriminator — the inner boot-PBP category is.

Decisive facts: **DLC does not boot** (`PARAM.PBP` or no PBP at all, never `EBOOT.PBP`), a **demo boots** (`EBOOT.PBP`), and a **patch** is `PBOOT.PBP` + `PG`. Demo-versus-full-game is *not* fully decidable: 2 of 3 sampled demos are `MG`, but `UP9000-NPUG80135_00-ECHOCHROMEDEMO00` is `EG` exactly like a full game. Do not invent a heuristic (content-ID `DEMO` substring was measured at 64 true / 26 false positives over 7,489 NPS content IDs — rejected). The plan surfaces that residue as an explicit conflict list instead.

Local ISO side: 1,785 distinct ISO SHA-1s in `catalog/iso/**`, 1,749 of which match the local Redump snapshot `.work/Sony - PlayStation Portable - Datfile (3545) (2026-09-11 01-48-58).zip` (3,545 discs; `<category>`: Games 3,271, Preproduction 107, Demos 91, Applications 34, Educational 34, Bonus Discs 7, Video 1). Both DAT variants carry `<category>`, so category totals need no second file.

## Approach

Steps 1–3 (ingest) must land and be re-ingested before step 5 produces non-`unknown` kinds. Steps 4 and 6–8 (website) only depend on step 3's record field names, so they may be written in parallel, but verification order is 1→3→4→…→9.

### 1. Retain SFO `CATEGORY` in the shared parser

`ingest/src/sfo.zig`:
- Add `category: ?[]const u8 = null` to `pub const Metadata` (line 5-10).
- Add `.{ "CATEGORY", "category" }` to the inline selected-key tuple at line 70. It then inherits the existing `.UTF8` / nonempty / unique / NUL-terminated / UTF-8 validation at lines 78-83 — no new validation code.
- Add a zig test asserting a `CATEGORY`-bearing SFO parses to `category == "MG"` and that a duplicate `CATEGORY` entry returns `error.InvalidSfo`, matching the existing test style in the same file.

No other record kind changes: `publish_iso` (`catalog.zig:135-145`), and the update/nand publishers build explicit `Metadata` structs and will simply not emit `category`. ISO/update revisions therefore stay at 6/2 and nothing is re-ingested except PKGs.

### 2. Capture the boot PBP's category during the PKG walk

`ingest/src/inventory.zig`, `pub const Result` (line 95): add

```zig
boot_file: ?[]const u8 = null,
boot_category: ?[]const u8 = null,
```

Both borrow existing memory (`boot_file` is a static literal; `boot_category` points into `pbp_sfo_bytes`), so `Result.deinit` is unchanged.

`ingest/src/processor.zig`, `PackageInventory.emit` (lines 211-224) currently hard-codes `USRDIR/CONTENT/EBOOT.PBP` and then *replaces* `result.metadata` wholesale at line 223, which would drop the outer category. Rewrite the body after `try self.inventory.emit_view(name, contents);` to:

- Return early unless `name` equals one of `"USRDIR/CONTENT/EBOOT.PBP"`, `"USRDIR/CONTENT/PBOOT.PBP"`, `"USRDIR/CONTENT/PARAM.PBP"`; keep the matched literal.
- Return early if `self.result.boot_file != null` (first match wins; measured packages contain exactly one).
- Parse as today (`containers.parse_pbp`, `sfo.parse` into `self.result.pbp_sfo_bytes` / `pbp_title`), keeping the existing `catch` that ignores malformed inner PBPs.
- Set `self.result.boot_file = <matched literal>` and `self.result.boot_category = inner.category`.
- Keep the existing metadata override **only for `EBOOT.PBP`** (unchanged precedence for `title`/`disc_id`/`disc_version`/`required_firmware`), and add `.category = self.result.metadata.category` to the struct literal so the outer category survives. For `PBOOT.PBP`/`PARAM.PBP` do not touch `result.metadata`: a patch's inner `DISC_ID` must not replace the package's own identity, which is a behavior change the current single-name match hid.

### 3. Publish the three new PKG fields and bump the revision

`ingest/src/catalog.zig`, `publish_pkg` (lines 108-131): add to the local `Metadata` struct and the literal at line 126, in this order after `title_id`:

```zig
category: ?[]const u8,        // outer PARAM.SFO CATEGORY: PP | 1P | MN | HG | null
boot_category: ?[]const u8,   // boot PBP PARAM.SFO CATEGORY: EG | MG | PG | ME | null
boot_file: ?[]const u8,       // "USRDIR/CONTENT/EBOOT.PBP" | ".../PBOOT.PBP" | ".../PARAM.PBP" | null
```

wired from `fields.category`, `result.boot_category`, `result.boot_file`. `emit_null_optional_fields = false` (`catalog.zig:178`) keeps absent values out of the JSON, exactly like today's optional fields.

`tools/extractor_versions.json`: `"pkg": "5"` → `"pkg": "6"`. No `schemas/record.schema.json` change: `metadata` is deliberately free-form (`schemas/record.schema.json:57-60`).

Then rebuild and re-ingest the 101 local packages into `catalog/pkg/v6/`, leaving v3/v4/v5 pairs intact (CONTRIBUTING.md:81-85):

```sh
(cd ingest && zig build -Doptimize=ReleaseSafe)
./ingest/zig-out/bin/pspdb-ingest /mnt/nas/dev/pspdb-pkgs/completed --catalog catalog
```

Update `ingest/tests/test_pkg_cli.py`: its `pkg_bytes` fixture (line 34) already builds an inner PBP SFO — extend that SFO to include `CATEGORY` and assert `record['metadata']['category']`, `['boot_category']`, `['boot_file']` for a normal game package, and assert the theme case (content_type 9, `.PTF` only) has none of the three.

### 4. One classifier, server-side

New `website/pspdb/psn.py`:

```python
KINDS = ('game', 'demo', 'dlc', 'patch', 'theme', 'psone_classic', 'minis', 'neogeo', 'unknown')

def package_kind(metadata):
    """Kind from observed PKG facts only; never from titles or content-ID text."""
```

Exact precedence (first match wins; `metadata` may be `None` or lack the fields, which yields `'unknown'`):

1. `content_type == 9` → `'theme'`
2. `boot_category == 'PG'` → `'patch'`
3. `boot_file` is absent, or does not end with `'/EBOOT.PBP'` → `'dlc'`
4. `content_type == 6` → `'psone_classic'`
5. `content_type == 15` → `'minis'`
6. `content_type == 16` → `'neogeo'`
7. `content_type in (7, 14)` and `boot_category == 'MG'` → `'demo'`
8. `content_type in (7, 14)` and `boot_category == 'EG'` → `'game'`
9. otherwise → `'unknown'`

Also in `psn.py`, the reference-side mapping used by coverage (NPS list name plus the `Type` column of `PSP_GAMES`):

```python
LIST_KINDS = {'PSP_GAMES': 'game', 'PSP_DEMOS': 'demo', 'PSP_DLCS': 'dlc',
              'PSP_THEMES': 'theme', 'PSP_UPDATES': 'patch', 'PSX_GAMES': 'psone_classic'}
TYPE_KINDS = {'MINIS': 'minis', 'NEOGEO': 'neogeo', 'PC ENGINE': 'pcengine'}

def reference_kind(lists, type_value):
    """One kind per reference content ID; NPS rows appear in several lists."""
```

`reference_kind` resolves multi-list membership by this precedence, which the measured overlaps require (`GAMEUPDATE…` IDs appear in both `PSP_DLCS` and `PSP_UPDATES`; demo IDs appear in `PSP_GAMES`/`PSP_DLCS`): `patch` > `theme` > `demo` > `dlc` > `psone_classic` > `TYPE_KINDS[type]` > `game`. `'pcengine'` is reference-only: no local PKG in the corpus has it, so it is not in `KINDS` and `package_kind` never returns it.

`website/pspdb/server.py`, `catalog_data` (line 110, inside the existing `for (kind, digest), (record, tree)` loop): add a `kind == 'pkg'` branch setting `record['psn_kind'] = package_kind(record.get('metadata'))`. Records stay otherwise untouched, exactly like the existing ISO annotation branch.

Clean cutover in `website/pspdb/web/app.js`: **delete** `packageGroup` (lines 641-653) and replace line 736 with `const category = pkg.psn_kind || "unknown";`. Every package now lands in a named group (previously `content_type` 7-without-flag and 14 landed directly under `psn`), so tree paths become `psn/<kind>/<sha256>.pkg`. The former `update` group name is replaced by `patch`; `psone_classic`, `minis`, `neogeo`, `theme`, `unknown` keep their spelling.

### 5. Population loaders (denominators)

`website/pspdb/redump.py`: factor the existing DAT/ZIP read + `datafile` validation (lines 10-25) into `def _read_datafile(source)` returning the parsed `ET` root, used by `load_matches` (behavior unchanged) and by a new:

```python
def load_population(source):
    """Every ISO disc in a Redump DAT, keyed for coverage rather than annotation."""
```

returning `{'name': header_name, 'version': header_version, 'discs': {(sha1, size): category}}` where `category` is `game.findtext('category') or 'Unknown'`, `name`/`version` come from `datafile/header/name` and `header/version`, and the same `.iso`-suffix / hex-SHA-1 / size validation as `load_matches` applies. A `<game>` with several `.iso` roms contributes one key per rom (multi-disc releases).

New `website/pspdb/nopaystation.py`:

```python
CATEGORIES = ('PSP_GAMES', 'PSP_DEMOS', 'PSP_DLCS', 'PSP_THEMES', 'PSP_UPDATES', 'PSX_GAMES')

def load_population(source):
    """Index NPS TSV snapshots by content ID; a directory or a single .tsv file."""
```

- `source` may be a directory (read every `*.tsv` in sorted order) or one `.tsv` file. Filenames must match `(?i)^(PSP_GAMES|PSP_DEMOS|PSP_DLCS|PSP_THEMES|PSP_UPDATES|PSX_GAMES)(\(\d+\))?\.tsv$` — the same shape `tools/psn_acquire.py:31` accepts, so browser-duplicated names like `PSX_GAMES(1).tsv` work. Non-matching `*.tsv` names raise `ValueError`; non-`.tsv` files in a directory (e.g. `README.md`, `manifest.json`) are ignored. Deliberate duplication rather than importing from `tools/`: the website is a separate uv package (`website/pyproject.toml`) and must not depend on repository-root scripts.
- Parse with `csv.DictReader(delimiter='\t')` over text decoded as `utf-8-sig`. Required headers: `Content ID`, `Region`, `Name`, `File Size`, `SHA256` (raise `ValueError` if `Content ID` is missing). `Type` is optional and only present in `PSP_GAMES`. Never read, retain, or log `RAP`/`zRIF`/`Download .RAP file` columns.
- Skip rows whose `Content ID` is empty. Normalize `SHA256` to lower-case when it is exactly 64 hex characters, else `None`; `File Size` to `int` when ASCII-decimal, else `None`.
- Identical snapshots are deduplicated by file SHA-256 before parsing, so a directory holding `PSX_GAMES(1).tsv` and `PSX_GAMES(2).tsv` with equal bytes counts once. Distinct snapshots of the same category are unioned by content ID.
- Return `{'lists': {category: {'snapshots': [sha256, …], 'content_ids': [...]}}, 'packages': {content_id: {'lists': [category, …], 'type': str|None, 'sha256': str|None, 'size_bytes': int|None}}}`, with all lists sorted for deterministic cache keys and JSON.

### 6. Coverage computation

New `website/pspdb/coverage.py`:

```python
def build(records, redump=None, nopaystation=None):
    """Population coverage from loaded reference snapshots; None when unavailable."""
```

Returns `None` when both reference arguments are `None`; otherwise a dict with exactly these keys (absent sections are `None`):

```jsonc
{
  "umd": {
    "source": {"name": "Sony - PlayStation Portable", "version": "2026-09-11 01-48-58"},
    "total": 3545, "present": 1749, "unmatched_local": 36,
    "categories": [{"name": "Games", "total": 3271, "present": 1647}, …]   // sorted by name
  },
  "psn": {
    "total": 7489, "present": 101, "unmatched_local": 0,
    "lists": [{"name": "PSP_GAMES", "total": 2458, "present": 21, "byte_verified": 19}, …],  // CATEGORIES order
    "kinds": [{"kind": "game", "local": 7, "reference": 3105}, …],          // KINDS order, then reference-only kinds
    "conflicts": [{"content_id": "UP9000-NPUG80135_00-ECHOCHROMEDEMO00",
                   "kind": "game", "reference_kind": "demo", "lists": ["PSP_DEMOS", "PSP_GAMES"]}, …]
  }
}
```

Definitions, chosen so the panel never shows a percentage above 100:
- `umd.present` = number of distinct Redump `(sha1, size)` keys matched by at least one ISO record (`record['sha1']`, `record['size_bytes']`) — the same exact key as `redump.load_matches`, never serials.
- `umd.unmatched_local` = ISO records with a `sha1` that matches no key (rebuilt/derived images; 36 today).
- `psn.total` = distinct reference content IDs; `psn.lists[].total` = distinct content IDs in that category.
- `psn.present` = distinct reference content IDs matched by a PKG record's `metadata.content_id`. `byte_verified` additionally requires the reference row's `sha256`+`size_bytes` to equal the record's `sha256`/`size_bytes`, mirroring the exact-identity rule in `tools/psn_acquire.py:catalog_identities`.
- `psn.kinds[].local` = PKG records per `record['psn_kind']`; `reference` = reference content IDs per `reference_kind(...)`.
- `psn.conflicts` = locally present content IDs where `psn_kind != reference_kind`, sorted by content ID, capped at 50 entries (the cap is the display contract; the count is still visible through `kinds`).

### 7. Wire the reference inputs through serve and export

- `website/pspdb/cli.py`: add `parser.add_argument("--nopaystation", help="Folder of NoPayStation TSV snapshots (or one .tsv) for PSN coverage totals")` beside `--umdatabase` (line 20), and pass `nopaystation=args.nopaystation` to both `export_site` and `serve`.
- `website/pspdb/server.py`: `catalog_data(catalog, redump=None, umdatabase=None, redump_population=None, nopaystation=None)`; after building `records`/`trees`, set `data['coverage'] = coverage.build(records, redump_population, nopaystation)`, returning `{'records': …, 'trees': …, 'coverage': …}`. `wire.encode_catalog` passes unknown top-level fields through untouched (`wire.py:86-90`) and `decodeCatalog` already copies every non-wire key (`app.js:1109-1110`), so no transport change is needed.
- `serve(catalog, port=8000, host="127.0.0.1", store=None, redump=None, umdatabase=None, nopaystation=None)`: load `redump.load_population(redump)` alongside the existing `load_matches(redump)` (one file, two indexes) and `nopaystation.load_population(nopaystation)` when the flag is given; pass both into `handler_for(catalog, store, matches, umd_matches, population, nps)`.
- `handler_for(catalog, store=None, redump=None, umdatabase=None, redump_population=None, nopaystation=None)` forwards to `_CatalogCache`.
- `_CatalogCache.__init__(self, catalog, store, redump, umdatabase, redump_population=None, nopaystation=None)`: keep both on `self`, pass them in the `catalog_data` call at line 348, and extend the two cache identities so changed reference data cannot serve a stale snapshot:
  - `implementation` (line 281-284): add `psn.py`, `coverage.py`, `nopaystation.py`, and `umdatabase.py` bytes (the last is missing today and is a live bug for UMDatabase annotations).
  - `cache_configuration` (line 285-288): append `json`-serializable digests, not the raw maps — `hashlib.sha256` over `json.dumps(..., sort_keys=True)` of the population dicts (they are large; the existing `sorted(...items())` style would bloat every disk-cache key).
- `website/pspdb/export.py`: `export_site(catalog, output, redump=None, umdatabase=None, nopaystation=None)` loads the same two populations and forwards them to `catalog_data`.
- `README.md`: document `--nopaystation` next to `--redump`/`--umdatabase` for both serve (around line 405-414) and export (around line 514-529), stating that coverage totals come only from supplied snapshots, that omitting a flag omits that section, and that `--redump` now feeds both exact ISO links and the UMD denominator.

### 8. Second top-level view in the browser

`website/pspdb/web/index.html`:
- Inside `<header>` after the brand (line 12), add `<nav class="views" role="tablist" aria-label="Views">` with two `<button role="tab" id="view-browse">Browse</button>` and `<button role="tab" id="view-coverage">Coverage</button>`, `aria-selected` / `aria-controls` pointing at `browser` and `coverage`.
- Add `<main id="coverage" hidden aria-labelledby="view-coverage">` as a sibling immediately after `main#browser` (line 38), containing empty `<section id="coverage-umd">`, `<section id="coverage-psn">`, and `<p id="coverage-empty" hidden>` for the "no reference snapshots supplied" state.

`website/pspdb/web/app.js`:
- Add `function selectView(name)` owning: `hidden` on `#browser`/`#coverage`, `hidden` on the tree-only chrome (`.search-bar`, `#selected-error`, `.selection-bar`, `footer`), `aria-selected`/`tabindex` on both tabs, and the URL (`?view=coverage` added or removed with `history.replaceState`, preserving existing `?q=` and the location hash, which the tree uses for selection). Search and tree state are untouched, so switching back restores the previous selection.
- Add `function buildCoverage(data)` rendering `data.coverage` into the two sections: UMD as `present / total` with a percentage and a `<table>` of `categories` (name, present, total, percent) plus an "unmatched local images" row; PSN as `present / total` with tables for `lists` (name, present, byte_verified, total) and `kinds` (kind, local, reference), then a `conflicts` table (content ID, local kind, reference kind, lists) with a caption naming the 50-row cap. When `data.coverage` is `null`, show `#coverage-empty` with the text `Serve with --redump and/or --nopaystation to see coverage.` and render no tables. Percentages are `Math.round(present / total * 1000) / 10` with one decimal, and `total === 0` renders `—`, never `NaN`.
- In the existing success callback (line 1119-1126), call `buildCoverage(data)` after `build(data)` and then `selectView(new URLSearchParams(location.search).get("view") === "coverage" ? "coverage" : "browse")` instead of the bare `$("browser").hidden = false;`. Wire both tab buttons to `selectView`.
- The error path (lines 1127-1135) additionally hides `#coverage`.

`website/pspdb/web/style.css`: style `.views` tabs (reuse the existing header/button variables) and `#coverage` tables; keep the existing `@media (max-width: 760px)` approach so the tab bar and tables stay usable narrow.

### 9. Tests

- New `website/tests/test_psn.py`: table-driven `package_kind` coverage of every precedence branch using the measured combinations (`9`/theme, `PG`+`PBOOT`/patch, `PARAM.PBP`/dlc, missing `boot_file`/dlc, `6`/psone_classic, `15`/minis, `16`/neogeo, `7`+`MG`/demo, `7`+`EG`/game, `14`+`EG`/game, unknown `content_type`/unknown, `None` metadata/unknown) plus `reference_kind` precedence (`['PSP_DLCS','PSP_UPDATES']` → patch, `['PSP_DEMOS','PSP_GAMES']` → demo, `['PSP_GAMES']` + `Type='Minis'` → minis).
- New `website/tests/test_coverage.py` (stdlib `unittest`, `tempfile`, synthetic fixtures like `website/tests/test_redump.py`): a two-disc DAT with differing `<category>` plus one matching and one non-matching ISO record proves `umd` totals/`present`/`unmatched_local`; a synthetic snapshot directory (including a duplicate `PSX_GAMES(1).tsv` byte copy, a `README.md` to ignore, and a row with an empty `SHA256`) plus PKG records proves `psn.lists`, `byte_verified`, `kinds`, and one `conflicts` row; `coverage.build(records)` with no references returns `None`. Add one `test_server.py`/`test_export.py` assertion that the decoded payload carries `coverage` and `records['pkg'][…]['psn_kind']`.
- `website/tests/tree-catalog.mjs`: update the two PSN fixtures. The `pkgFixture` (lines 153-162) must carry `psn_kind:'neogeo'` for the `psn/neogeo/…` path assertion to survive the cutover, and the `updateFixture` block (lines 180-187) must set `psn_kind` per record (`'patch'`, `'game'`, `'theme'`, `'dlc'`) and assert the resulting `psn/<kind>/…` paths — its `package_flags & 0x10` expectation is deleted, not re-pinned, because that heuristic no longer exists.
- `website/tests/browser-tree.mjs`: add checks that both tabs exist with correct `aria-selected`, that clicking `Coverage` hides `#browser` and shows `#coverage`, that returning to `Browse` preserves the previously selected tree row, and that `?view=coverage` opens directly on the panel.

## Critical files & anchors

- `ingest/src/processor.zig:211-224` — `PackageInventory.emit`; the single place that sees decrypted PKG entries, and where the wholesale `result.metadata` overwrite at line 223 must stop dropping the outer category.
- `ingest/src/catalog.zig:108-131` — `publish_pkg`; the exact published PKG metadata shape, and the `revisions.pkg` use that the version bump keys off.
- `website/pspdb/server.py:59-124, 267-288, 341-356, 401-405, 518-530` — `catalog_data`, `_CatalogCache` identity, refresh, `handler_for`, `serve`: every place the two new reference inputs and the `coverage` field must be threaded.
- `website/pspdb/web/app.js:641-653, 729-746, 1119-1135` — classifier to delete, PSN grouping to repoint at `psn_kind`, and the load callback where the new view is initialized.
- `.work/Sony - PlayStation Portable - Datfile (serial,version) (3545) (2026-09-11 01-48-58).zip` and `.work/nopaystation/manual-2026-09-12/` — the real reference snapshots used for end-to-end verification; the NPS directory is exactly why the loader must tolerate `(1)` suffixes and non-TSV files.

## Verification

Prerequisites: repository root, `uv sync --locked` done, zig toolchain available, `/mnt/nas` mounted (the NAS holds the 101 PKGs for re-ingest).

1. Ingest unit + CLI proof:
   ```sh
   (cd ingest && zig build test)
   uv run --locked python -m unittest discover -s ingest/tests
   ```
2. Re-ingest and inspect one real record of each shape (new behavior, concrete expectation):
   ```sh
   (cd ingest && zig build -Doptimize=ReleaseSafe)
   ./ingest/zig-out/bin/pspdb-ingest /mnt/nas/dev/pspdb-pkgs/completed --catalog catalog
   ```
   `catalog/pkg/v6/` must contain 101 `-ingest.json`/`-tree.json` pairs. A patch package (e.g. content ID `JP0101-NPJH50721_00-GAMEUPDATE000101`) must show `"category": "PP"`, `"boot_category": "PG"`, `"boot_file": "USRDIR/CONTENT/PBOOT.PBP"`; the DLC `JP0700-NPJH50701_00-SAOIMADDCOSTUME1` must show `"boot_category": "MG"`, `"boot_file": "USRDIR/CONTENT/PARAM.PBP"`; a theme (`HP9000-NPHW00012_00-THMTLOCOROCOCHN5`) must have none of the three fields.
3. Python + model suites:
   ```sh
   uv run --locked python -m unittest discover -s website/tests
   uv run --locked python -m unittest discover -s tools/tests
   node website/tests/tree-catalog.mjs
   ```
4. End-to-end panel proof with the real snapshots:
   ```sh
   uv run pspdb-web --catalog catalog --port 8000 \
     --redump '.work/Sony - PlayStation Portable - Datfile (serial,version) (3545) (2026-09-11 01-48-58).zip' \
     --nopaystation .work/nopaystation/manual-2026-09-12
   ```
   Drive it with the browser tool and read the Coverage tab. Expected observable values from the measured corpus:
   - UMD: total `3545`, present `1749` (49.3%), unmatched local `36`; `Games` row `1647 / 3271`; `Video` row `1 / 1`.
   - PSN kinds (`local` column), summing to 101: `game 7`, `demo 3`, `dlc 2`, `patch 67`, `theme 3`, `psone_classic 13`, `minis 5`, `neogeo 1`, `unknown 0`.
   - At least one conflict row, including `UP9000-NPUG80135_00-ECHOCHROMEDEMO00` with local kind `game` and reference kind `demo`.
   - Tree view: `psn/patch/…`, `psn/dlc/…`, `psn/demo/…` groups exist and no package sits directly under `psn`.
   If a `present` number differs from the above, report the measured value and confirm `present + missing == total` per section rather than tuning the classifier to hit these figures.
5. Static export parity:
   ```sh
   uv run --locked pspdb-web export --catalog catalog --output .work/coverage-preview \
     --redump '.work/Sony - PlayStation Portable - Datfile (serial,version) (3545) (2026-09-11 01-48-58).zip' \
     --nopaystation .work/nopaystation/manual-2026-09-12
   uv run --locked python -m http.server --directory .work/coverage-preview 8001
   ```
   The exported site's Coverage tab must show the same numbers as step 4, and `?view=coverage` must deep-link to the panel.
6. Catalog consistency after the revision bump:
   ```sh
   uv run --locked python tools/validate_catalog.py
   uv run --locked python tools/catalog_status.py --catalog catalog
   ```

## Assumptions & contingencies

- **`/mnt/nas/dev/pspdb-pkgs/completed` stays available.** If the NAS is not mounted, skip step 2's re-ingest, keep the ingest code change, and verify the classifier with the synthetic fixtures in `ingest/tests/test_pkg_cli.py` plus `website/tests/test_psn.py`; the panel will then report `unknown 101` and that is the correct honest output for un-re-ingested records — do not backfill kinds from `content_type` alone.
- **NPS snapshots come from disk, never the network.** The website must not fetch. If fresher lists are wanted, run `uv run --locked python tools/psn_acquire.py --work .work/psn-acquire --limit 0` first and point `--nopaystation` at `.work/psn-acquire/snapshots`; that fetch returned HTTP 403 for some user agents during research, so the committed `.work/nopaystation/manual-2026-09-12` directory remains the verification input.
- **Reference data is a floor, not truth.** Redump's 3,545 discs and NPS's ~7,489 content IDs are catalogs of *known* releases; the panel must label them as the supplied snapshot ("Redump 2026-09-11", list names) rather than "all PSP releases".
- If a future PKG turns up with `content_type` outside `{6, 7, 9, 14, 15, 16}`, `pkg.zig:51-54` rejects it at ingest, so `package_kind` will never see it; leave the `'unknown'` fallback in place rather than widening the accepted set.
