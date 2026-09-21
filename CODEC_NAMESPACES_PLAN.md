# Per-chip codec namespaces and the model-equivalence record

## Context

Two deliverables. First, the `*_0Ng.prx` hardware-generation builds must stay
fully available in the offline bindings — a program should run on every PSP
model, the firmware already loads exactly one generation's build, and there is
to be **no** `psp_options.model` field and no `Model` enum. The one place where
a per-model build changes what a caller observes is the audio codec family,
whose builds register four *different* module names for one identical library;
that must resolve through the existing reviewed `module_namespaces` mechanism
with no change to the public options surface. Second, the knowledge base must
record the measured per-model API equivalence, because the vault currently
asserts the opposite conclusion. End state for the code: `sceCodec_driver`
resolves its provider module on every release instead of refusing.

## Measured facts this plan depends on

Measured this session from the pinned PSPLibDoc snapshot
(`353caeb1322c4dad5f1dfe1c74fa3000e17e52a3`) with the reviewed
`module_namespaces` in `tools/bindings/import_policy.json` applied.

Sixteen model families exist (`codec`, `display`, `eflash`, `hpremote`,
`impose`, `input`, `loadexec`, `memlmd`, `mesg_led`, `pops`, `power`,
`skype_ve`, `umdcache`, `usb1seg`, `usbdmb`, `wlanfirm`). Comparing every
build's exported `(library, kind, NID)` set release by release:

- **Fifteen families are identical across all builds on every release they
  share** — same library names, same NIDs, same counts. They are the same API
  with a different hardware backend, e.g. at 6.60 `power_01g` … `power_11g` all
  export exactly 88 `scePower_driver` identities, `impose_*` all 31,
  `display_*` all 46 `sceDisplay_driver` + 23 `sceDisplay`.
- **`display` is the single family whose export set varies**, and only by
  *additional* panel/TV libraries, never by disagreeing on a shared one. At
  6.60: `display_01g` and `display_11g` export only `sceDisplay` +
  `sceDisplay_driver`; `display_02g` adds `sceDve_driver` (24) and
  `sceHibari_driver` (33); `display_03g`, `_04g`, `_05g`, `_09g` add
  `sceDve_driver` and `sceSamantha_driver` (41); `display_07g` adds
  `sceDve_driver` and `sceTmdlcd_driver` (36). Those panel libraries have
  distinct names, so they never collide — a model that lacks the panel simply
  has no provider for that library.
- **`codec` is the only family where the module *name* differs per build**
  while the exported identities stay identical (16 `sceCodec_driver` exports in
  every build):

  | Module file | Registered module | Releases |
  |---|---|---|
  | `codec.prx` | `sceWM8750_Driver` | 1.00–5.55 |
  | `codec_01g.prx` | `sceWM8750_Driver` | 6.00–6.61 |
  | `codec_02g.prx`, `codec_03g.prx` | `sceWM1800_Driver` | 6.00–6.61 |
  | `codec_04g.prx` | `sceWM1801_Driver` | 5.70–6.61 |
  | `codec_07g.prx`, `codec_09g.prx` | `sceWM1801_Driver` | 6.30–6.61, 6.60–6.61 |
  | `codec_05g.prx` | `sceCS42L52_Driver` | 5.70–6.61 |

  Each build exports `sceCodec_driver` and `syslib` and nothing else. This is
  the sole cause of the 38 remaining `several provider modules (sceCS42L52_Driver,
  sceWM1800_Driver, sceWM1801_Driver, sceWM8750_Driver)` rejections; 107
  identities live in `sceCodec_driver`.

Consequence, and the reason this plan contains no `Model` enum: for fifteen
families the union the generator already emits is exactly right, and for
`display` the differences are separate libraries that resolve on their own. Only
the codec module *string* is model-dependent, and a namespace split expresses
that offline without asking a program to declare hardware.

## Approach

### 1. Split the codec builds by registered module name

Append seven entries to `module_namespaces` in
`tools/bindings/import_policy.json`, following the existing entries' shape
exactly (`prx_name`, `module_name`, `libraries` map, `reason`). Only
`sceCodec_driver` moves; `syslib` is deliberately left unlisted so the shared
module-lifecycle exports keep their catalog name, matching how the codec/mpegbase
entries already treat `syslib`.

| `prx_name` | `module_name` | `libraries` |
|---|---|---|
| `codec_02g.prx` | `sceWM1800_Driver` | `{"sceCodec_driver": "sceCodec_WM1800"}` |
| `codec_03g.prx` | `sceWM1800_Driver` | `{"sceCodec_driver": "sceCodec_WM1800"}` |
| `codec_04g.prx` | `sceWM1801_Driver` | `{"sceCodec_driver": "sceCodec_WM1801"}` |
| `codec_07g.prx` | `sceWM1801_Driver` | `{"sceCodec_driver": "sceCodec_WM1801"}` |
| `codec_09g.prx` | `sceWM1801_Driver` | `{"sceCodec_driver": "sceCodec_WM1801"}` |
| `codec_11g.prx` | `sceWM1801_Driver` | `{"sceCodec_driver": "sceCodec_WM1801"}` |
| `codec_05g.prx` | `sceCS42L52_Driver` | `{"sceCodec_driver": "sceCodec_CS42L52"}` |

Namespace names are chosen after the audio DAC each build drives, because that
is what actually differs; they are not model tags, since several generations
share one chip. `codec.prx` and `codec_01g.prx` are **not** listed: both
register `sceWM8750_Driver`, so leaving them in place gives the base
`sceCodec_driver` a single provider name across 1.00–6.61 (60 releases).

Write one `reason` per entry stating: the codec builds export an identical
16-function `sceCodec_driver` surface but register a different module name per
audio DAC (`sceWM8750_Driver`, `sceWM1800_Driver`, `sceWM1801_Driver`,
`sceCS42L52_Driver`), so the namespace names the chip a caller resolves through
while the union of identities stays available offline.

Simulated outcome, to be reproduced by the implementer: 0 identities in
`sceCodec_driver` remain ambiguous, and 244 provider occurrences move —
`sceCodec_WM1800` 76, `sceCodec_WM1801` 119, `sceCodec_CS42L52` 49.

No `library_groups` entry is added: each new namespace holds exactly one
library, and the existing ungrouped-library rule gives it its own file. Do not
group the three chips together — they are alternative providers, and one group
file would restate the same NIDs three times and fail generation with
`reviewed namespace … restates function 0x…`.

### 2. Regenerate and install

Regenerate the tree with the extended policy and install the reviewed preview.
No generator code changes are required: `Catalog.namespace_providers` in
`tools/bindings/psplibdoc.py` already performs per-module library renaming,
keeps `library_name` (`"sceCodec_driver"`) on the moved identities, mirrors the
source library's typed wrappers into the namespace, and emits a `call` compile
error naming the source library. The new namespaces will contain metadata
declarations only, since `sceCodec_driver` has no reviewed import source in
`import_policy.json` `sources` and therefore no static import in the base
library either.

Commands are in **Verification**; the regeneration is the change.

### 3. Correct the knowledge base

`~/obsidian/llm/devices/psp/Firmware-Aware Bindings and NID Exports.md`
currently contains, under `### The title-visible module surface (2026-09-20)`,
a numbered class 2 reading:

> 2. **Hardware-generation builds** — 36 libraries provided by `*_0Ng.prx` sets
>    (`power_01g`…`power_11g`, `display_*`, `impose_*`, `codec_01g`…). One per
>    PSP model; at most one is resident on a given device, so the catalog's
>    union is not a real ambiguity. Needs a model axis, not a namespace.

The last sentence is now contradicted by measurement. Replace that list item
with a subsection recording what the per-build comparison found and the
decision it produced. Required content, in the note's existing terse style —
facts first, decision stated inline, no hedging:

- Sixteen model families, eight generations (`01 02 03 04 05 07 09 11`),
  88 module files.
- Fifteen families export an identical `(library, kind, NID)` set from every
  build on every shared release: at 6.60 each `power_0Ng` exports the same 88
  `scePower_driver` identities, each `impose_0Ng` the same 31, each
  `display_0Ng` the same 46 `sceDisplay_driver` and 23 `sceDisplay`. The builds
  are one API over different silicon, so the catalog union is exactly right and
  no per-program model selector is warranted.
- `display` is the one family whose export set varies, and only by adding
  panel/TV libraries under distinct names: `01g` and `11g` add none; `02g` adds
  `sceDve_driver` + `sceHibari_driver`; `03g`, `04g`, `05g`, `09g` add
  `sceDve_driver` + `sceSamantha_driver`; `07g` adds `sceDve_driver` +
  `sceTmdlcd_driver`. Distinct names never collide, so a model lacking the
  panel simply has no provider.
- `codec` is the only family where the registered module *name* differs while
  the 16 exported identities stay identical — reproduce the module/release
  table from the **Measured facts** section of this plan — and it is therefore
  the only model-related ambiguity. Record the resolution: per-chip namespaces
  `sceCodec_WM1800`, `sceCodec_WM1801`, `sceCodec_CS42L52`, with
  `sceWM8750_Driver` (`codec.prx` 1.00–5.55 and `codec_01g.prx` 6.00–6.61)
  staying in the base `sceCodec_driver`.
- State the rejected design explicitly so it is not revisited: a `Model` enum
  and a `psp_options.model` field were considered and dropped, because a
  program should run on all hardware, the firmware loads exactly one build, and
  the offline bindings must keep every possibility.

Update the section's closing line `Residual `several provider modules`
rejections: 741.` to the count measured in **Verification** step 3 (expected
670: 741 today minus the 71 occurrences in `src/c/library/sceCodec.zig`). If
the measured number differs, write the measured one.

Also extend class 1's list of namespaced variant builds in the same section
with the codec entries, so the two mechanisms read as one policy rather than
two, and bump the counts there (`Eleven reviewed modules now move 366 provider
occurrences over 328 identities`) to the values from the regenerated manifest.

`~/obsidian/llm/devices/psp/README.md` line 29 already indexes this note; its
summary does not enumerate sections, so it needs no edit. Do not create a new
note — this material belongs with the catalog/bindings record it corrects.

## Critical files & anchors

- `tools/bindings/import_policy.json` — `module_namespaces` array (starts line 5);
  the `mpegbase.prx` entry is the closest shape to copy, including a
  multi-library `libraries` map and a prose `reason`.
- `tools/bindings/psplibdoc.py` — `Catalog.namespace_providers` (≈171) and
  `_restrict` (≈147): the split's semantics, including the duplicate-NID guard
  that forbids putting two chips in one namespace.
- `src/c/library/sceCodec.zig` — current state, 71 `several provider modules`
  occurrences; the file to diff after regeneration.
- `~/obsidian/llm/devices/psp/Firmware-Aware Bindings and NID Exports.md` —
  section `### The title-visible module surface (2026-09-20)` (≈351) holds the
  three-class taxonomy and the residual-rejection count this change invalidates.

## Verification

Run from `/home/ryp/dev/sudoku-zig/Zig-PSP`. Prerequisite: a PSPLibDoc clone at
the pinned revision. If `/tmp/psplibdoc-snapshot` is missing, recreate it:
`git clone https://github.com/pspdev/psplibdoc.git /tmp/psplibdoc-snapshot && git -C /tmp/psplibdoc-snapshot checkout 353caeb1322c4dad5f1dfe1c74fa3000e17e52a3`.
`--pspsdk-dir pspsdk` is mandatory: the pinned PSPSDK revision
`863319e162cd39bcdfc86866e6310c520cd6a06e` is the in-repo fork and the default
clone URL cannot resolve it.

1. Two previews, byte-identical:
   `python3 tools/generate_bindings.py --pspsdk-dir pspsdk --psplibdoc-dir /tmp/psplibdoc-snapshot --output-dir .zig-cache/bindings-codec-a`,
   the same with `-b`, then `diff -qr .zig-cache/bindings-codec-a .zig-cache/bindings-codec-b`
   (no output expected).
2. New behaviour, exact expected content. In
   `.zig-cache/bindings-codec-a/src/c/library/`:
   - `grep -c 'several provider modules' sceCodec.zig` → `0` (was 71).
   - `grep -o '\.module = "[^"]*"' sceCodec.zig | sort -u` → only
     `.module = "sceWM8750_Driver"`.
   - Files `sceCodec_WM1800.zig`, `sceCodec_WM1801.zig`, `sceCodec_CS42L52.zig`
     exist; each contains `.library_name = "sceCodec_driver"` and a single
     distinct `.module` string matching its name, and none contains
     `several provider modules`.
   - `grep -n 'sceCodec_WM1801' ../modules.zig` shows the namespace registered
     in `all_libraries`.
   - Manifest counters rise by the simulated amounts:
     `python3 -c "import json;c=json.load(open('.zig-cache/bindings-codec-a/src/c/bindings-manifest.json'))['catalog']['counts'];print(c['namespaced_modules'],c['namespaced_provider_occurrences'])"`
     → `18` and `610` (11 modules / 366 occurrences today, plus 7 modules / 244
     occurrences). If the counts differ, re-derive them before proceeding rather
     than adjusting the expectation.
3. Install and build:
   `python3 tools/generate_bindings.py --install-preview .zig-cache/bindings-codec-a`,
   then `python3 -m unittest discover -s tools -p test_generate_bindings.py`,
   `python3 -m unittest discover -s tools/bindings/tests -p 'test_*.py'`,
   `zig build test-imports`, `zig build test examples docs`,
   `(cd examples && zig build)`. All must pass; no root declares anything new,
   because the public options surface is unchanged.
4. Compile-time proof that the split resolves a real call site. Create
   `examples/codec_smoke.zig` copying the preamble of `examples/impose_demo.zig`
   (`pub const psp_options: sdk.Options = .{ .firmware = .v6_60 };`, `panic`,
   `std_options_debug_threaded_io`, `std_options_debug_io`, `std_options_cwd`,
   the `module_info` asm block), with:

   ```zig
   const wm8750 = sdk.c.sceCodec.sceCodecOutputEnable;
   const wm1801 = sdk.c.sceCodec_WM1801.sceCodecOutputEnable;
   comptime {
       if (!std.mem.eql(u8, wm8750.module_name, "sceWM8750_Driver")) @compileError(wm8750.module_name);
       if (!std.mem.eql(u8, wm1801.module_name, "sceWM1801_Driver")) @compileError(wm1801.module_name);
       if (!std.mem.eql(u8, wm8750.library_name, wm1801.library_name)) @compileError("library name diverged");
       if (wm8750.nid != wm1801.nid) @compileError("nid diverged");
   }
   pub fn main() void {}
   ```

   Register it in the `examples` array in `examples/build.zig`, run
   `(cd examples && zig build)`, and confirm `examples/zig-out/bin/example_codec_smoke`
   is produced — the comptime block passing is the proof. If
   `sceCodecOutputEnable` is not the declaration name in the generated files,
   take any name present in `sceCodec.zig`; the assertions do not depend on
   which export it is. Delete the file and its `examples/build.zig` entry
   afterwards.
5. Residual-rejection count for the knowledge-base edit, after step 3's
   install: `grep -c 'several provider modules' src/c/library/*.zig | awk -F: '{s+=$2} END {print s}'`
   → expected `670` (741 before, minus the 71 occurrences in `sceCodec.zig`).
   Write whatever this prints into the note; do not carry the expectation over
   if it differs.
6. Knowledge-base edit lands and stays consistent:
   `grep -n 'Needs a model axis' "$HOME/obsidian/llm/devices/psp/Firmware-Aware Bindings and NID Exports.md"`
   returns nothing, and
   `grep -n 'sceWM1801_Driver\|identical .*export set\|no per-program model' "$HOME/obsidian/llm/devices/psp/Firmware-Aware Bindings and NID Exports.md"`
   returns the new per-model equivalence text plus the codec table.

## Assumptions & contingencies

- **No `psp_options.model` and no `Model` enum.** Model-generation builds stay
  unioned in the offline bindings exactly as today; a program keeps running on
  every PSP model, and the firmware's choice of which `*_0Ng.prx` is resident is
  a runtime fact the bindings do not model. This deliberately leaves the
  release gates of the 39 model-provided libraries as the union across
  generations.
- **Panel libraries stay as they are.** `sceSamantha_driver`,
  `sceHibari_driver`, `sceTmdlcd_driver` and `sceDve_driver` are exported only
  by the `display_*` builds that carry that panel, under distinct library names,
  so they already resolve to one module and need no policy entry. If
  regeneration reports a `several provider modules` rejection inside any of
  them, it is a different collision than the one measured here: add a
  `module_namespaces` entry for the offending module following step 1's shape
  rather than changing the panel libraries' names.
- **Chip-named namespaces, not model-named.** `sceCodec_WM1800` /
  `sceCodec_WM1801` / `sceCodec_CS42L52` are named after the DAC because four
  chips span eight generations; if review prefers the base library's full
  spelling, rename the targets to `sceCodec_driver_WM1800` and so on in the same
  policy entries — only the `libraries` map values and the generated file names
  change.
