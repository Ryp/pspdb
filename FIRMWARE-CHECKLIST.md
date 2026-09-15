# PSP official firmware collection checklist

## Scope and counting rules

Keep three separate inventories:

1. **Release labels:** Sony retail OFW versions, including factory-only and UMD-distributed releases.
2. **Artifacts/builds:** distinct original bytes, hardware-target packages (especially PSP Go), regional/channel variants, and same-version revisions. SHA-256 identifies an artifact; a version string does not.
3. **Non-retail material:** development/test firmware, prototypes, recovery/factory images, and CFW. Track separately; do not silently include these in a retail count.

A release can lack a public updater. A loose PSAR, flash dump, or reconstructed PBP must not be labelled an original Sony distribution without provenance. Archive ZIPs and their contents are separate objects, not necessarily different firmware builds.

### Retail release census

The reconciled baseline is **61 documented consumer-visible retail OFW version labels**, from 1.00 through 6.61. This is not a count of every binary build, development firmware, or prototype that ever existed.

- **51** generally released updater version labels.
- **6** preinstalled-only version labels: 1.00, 3.60, 4.20, 4.21, 5.70, 6.50.
- **4** UMD-only update version labels: 3.96, 5.05, 5.55, 6.36.

Cross-check the [OFW history](https://www.psdevwiki.com/psp/Official_Firmware_(OFW)) against [Darthsternie's archive](https://darthsternie.net/psp-firmwares/). The latter lists those 61 distinct labels in **64 standard-table artifact rows**, plus **11 PSP Go rows** (75 rows total). This is archive coverage, not 75 independent firmware releases or authenticated original packages. It includes duplicate representations of 3.60 and 4.21 and two packages labelled 2.00 v1/v2. All 75 archive rows and two additional same-version artifacts have now been acquired; hashes, provenance classifications, original UMD component recoveries, and remaining gaps are recorded in `<backup-root>/ofw-updaters/manifest.json`. Most files have not undergone Sony cryptographic authentication. The archive's `100.PBP` is the non-retail Bogus build 106 (`APP00(balloon)`), not an original retail 1.00 updater.

| Family | Count | Labels in that archive |
| --- | ---: | --- |
| 1.xx | 4 | 1.00, 1.50, 1.51, 1.52 |
| 2.xx | 9 | 2.00, 2.01, 2.50, 2.60, 2.70, 2.71, 2.80, 2.81, 2.82 |
| 3.xx | 21 | 3.00, 3.01, 3.02, 3.03, 3.10, 3.11, 3.30, 3.40, 3.50, 3.51, 3.52, 3.60, 3.70, 3.71, 3.72, 3.73, 3.80, 3.90, 3.93, 3.95, 3.96 |
| 4.xx | 5 | 4.00, 4.01, 4.05, 4.20, 4.21 |
| 5.xx | 9 | 5.00, 5.01, 5.02, 5.03, 5.05, 5.50, 5.51, 5.55, 5.70 |
| 6.xx | 13 | 6.00, 6.10, 6.20, 6.30, 6.31, 6.35, 6.36, 6.37, 6.38, 6.39, 6.50, 6.60, 6.61 |

The census is a documented retail baseline, not a closed universe for all firmware builds. Do not promote an undocumented numeric gap into a release. In particular, 6.07 is not supported by the reconciled retail lists and is not included. Internal build/version labels must be recorded separately from displayed retail release labels.

Distribution classifications are also recorded in the [preserved full version-history table](https://ultimatepopculture.fandom.com/wiki/PlayStation_Portable_system_software). Artifact enumeration can be reproduced from the [Internet Archive metadata manifest](https://archive.org/metadata/psp_ofw_firmwares); do not treat that mirror as a second independent publisher of the firmware bytes.

## Per-release and per-artifact checklist

### Identity and original evidence

- [ ] Record displayed version, internal build identifiers, devkit version, release/build dates, and model-generation targets separately.
- [ ] Record release channel: web/network updater, UMD update, factory-installed, service/recovery, or other evidenced source.
- [ ] Preserve original PBP/PSAR/image bytes and original filename; calculate SHA-256, byte length, and legacy hashes needed to compare historical sources.
- [ ] Record source URL or physical-media identifier, acquisition date, archive/container ancestry, publisher-claimed hashes, and independent corroboration.
- [ ] Separate PSP Go and standard packages; record regional or same-version differences by actual hash, not filename assumptions.
- [ ] Inventory known-but-missing versions and variants explicitly. Record why a package is missing or inapplicable rather than fabricating an updater.

### Package contents and decoded derivatives

- [ ] Preserve every PBP section, including PARAM.SFO, artwork/audio, DATA.PSP (the updater executable), and DATA.PSAR.
- [ ] Preserve SFO fields, PSAR headers and filename/model-selection tables, original record ordering, repeated names, and extraction diagnostics.
- [ ] Inventory all payload files with raw hash/size, resolved path, model predicates, source record, and parent artifact.
- [ ] Preserve original encrypted/compressed bytes alongside decrypted/decompressed outputs; retain the complete transformation ancestry.
- [ ] Record PRX/module names, attributes, imports/exports/NIDs, tags, compression formats, and undecoded/unsupported objects.
- [ ] Preserve all IPL variants and obtainable decoded stages, embedded reboot code, updater helper modules, and other embedded update payloads.
- [ ] Record the exact extractor revision, patches, parameters, dependencies, and required device context. Keep failed and partial extraction distinct from success.
- [ ] Record authentication results separately from successful decryption: signatures, CMACs, CRCs, bounds checks, and checks not implemented. A parser accepting bytes is not proof of Sony authenticity.

### Installer behavior: source-state to destination-state

For each behavior claim, attach a code location/disassembly, observed trace, or experiment; identify the updater hash, model, source firmware, destination firmware, and limitations.

- [ ] Map updater entry points and all loaded helper modules, including their own versions and hashes.
- [ ] Identify version, model/minimum-firmware, region, power/battery, storage-space, and package-integrity checks; distinguish official checks from downgrader bypasses.
- [ ] Recover model-selection and filename mapping rules, conditional payload selection, and installation order.
- [ ] Identify partition creation/formatting, file deletion/replacement/preservation, attributes, and generated files for every partition actually present.
- [ ] Identify IPL selection/writes and any IdStorage modifications; list exact affected keys/ranges or explicitly record that this is unknown.
- [ ] Identify any other controller/firmware update actions and required conditions. Do not assume every release touches Syscon or other controllers.
- [ ] Identify activation, settings, registry, resume/hibernation, and model-specific data preservation or migration.
- [ ] Separate updater actions from first-boot initialization/migration. Capture failure, interruption, recovery, and rollback behavior only where supported by evidence.
- [ ] Produce an installation manifest with operations and predicates, not merely a flattened list of extracted files.

### Installed-state corroboration

- [ ] Record hardware generation, board identifiers where known, NAND/storage geometry, region, running firmware, minimum-firmware evidence, and prior CFW/modification history.
- [ ] Preserve raw NAND with spare data, bad-block information, dump-tool revision/options, checksums, and any fuse/scramble context needed for offline interpretation.
- [ ] Inventory the actual partition table; do not assume every device has exactly flash0 through flash3.
- [ ] Capture logical file inventories and hashes, IPL, IdStorage, and relevant separate storage such as PSP Go internal storage. Memory Stick content is not included in a NAND dump.
- [ ] For controlled comparisons, distinguish before-update, immediately-after-update, and first-boot states; associate every snapshot with the exact transition.
- [ ] Compare installed payloads with package-derived expectations. Classify generated data, per-device data, preserved leftovers, missing files, and modifications separately.
- [ ] Check dump size, logical mapping, filesystem consistency, and available ECC/integrity checks; state exactly which were exercised. A readable image is not a restore test.
- [ ] Do not perform unsupported downgrades or restore another console's image to obtain coverage. Chronoswitch compatibility is not a guarantee of safe experimentation.

### Completion and gaps

- [ ] Track package acquisition, extraction, authentication, installer analysis, and installed-state corroboration as separate statuses.
- [ ] Mark each item complete, partial, missing, unknown, or not applicable with evidence. Do not treat absence of an updater as absence of a release.
- [ ] Publish counts by release label, distinct artifact hash, build/model variant, and evidence status; avoid a single ambiguous firmware count.
- [ ] Keep immutable boot ROM/pre-IPL and per-device provisioning in related hardware inventories, not conflated with OFW release payloads.

## Chronoswitch research checkout

- Upstream: https://github.com/DaveeFTW/chronoswitch
- Local path: `.work/chronoswitch`
- Examined commit: `c57a8b7d1039dcba5da8b01c504cc7852c13c9a1`
- It launches a supplied Sony updater after patching restrictions. It is not a full replacement implementation of Sony's installation logic and is not an exhaustive firmware history.
- `src/main.c:get_updater_version` reads `UPDATER_VER` from the updater SFO. The README explicitly requires a separate PSP Go updater and internal-storage path.
- `src/main.c` checks reported versus Baryon-inferred hardware, handles the PSP Go resume-game state, and rejects an 11g target below 6.60.
- `src/patch_table.h` and `src/rebootex.c` contain source-firmware-specific patch data for 6.31, 6.35, 6.38, 6.39, 6.60, and 6.61. These are supported patch contexts, not the complete list of OFW releases or installation targets.
- The `src/downgrade_ctrl` and `src/downgrade660_ctrl` payloads are the main leads for tracing updater restrictions and modifications. Sony's actual updater and helper binaries remain necessary for exact installer behavior.
- `src/downgrade660_ctrl/main.c:123-160` reads IdStorage leaf `0x51` for a device minimum version, with a PSP-1000 fallback and a special 09g path. Capture that input and the branch taken; do not turn this bypass policy into Sony's universal compatibility rule.
- `src/downgrade660_ctrl/main.c:163-170` specially spoofs the updater's `sceKernelDevkitVersion` call for 6.61 to 6.60. Source-version effects therefore belong in the transition matrix.
- `src/downgrade660_ctrl/main.c:182-248` redirects 04g index-file reads to the 09g name and substitutes certificate data in memory during a check. This is not evidence that it persistently rewrites those IdStorage leaves.
- `src/downgrade660_ctrl/main.c:251-307` intercepts `sceLflashFatfmtUpdater` to disable Infinity redirection and hooks decrypted index/version data through `sceResmgr`. These are useful observation points, but the underlying Sony formatter/updater still determines installation contents.

## Evidence already collected locally

Paths below use `<backup-root>` for the private PSP backup directory and
`<console-id>` for a console's backup subdirectory. Device fuse IDs are retained
privately with the dumps, not published here.

- PSP-1000 / 01g: raw 33 MiB NAND, installed version 6.60, updater log recording 6.35 to 6.60. Includes configuration remnants, so this is not a controlled clean-install baseline.
- Other PSP / 09g firmware: raw 66 MiB NAND, installed version 6.61 with ARK modules, updater log recording 6.60 to 6.61. Not an unmodified OFW baseline.
- Both have decoded FAT images, boot/IdStorage derivatives, and checksums under `<backup-root>/<console-id>/`.
- Neither snapshot alone proves what the historical updater changed; logs and current contents are separate evidence.
- Existing `pspdb` PSAR extraction preserves model tables, reboot/IPL derivatives, and provenance, but its README explicitly distinguishes decoded package tables from complete installed filesystems. Authentication coverage also has documented limitations.
- The Zig-PSP NAND tool exports the active IPL with `zNANDTool NAND.bin --ipl IPL.bin`. The PSP-1000 export at `<backup-root>/<console-id>/ipl.bin` exactly matches OFW 6.60 PSAR record `00522`, mapped to `ipl:/nandipl_01g.bin`: 131,072 bytes, SHA-256 `e30d80a6a24d0d4d84cffbaeaf2dfd009b9ec949a91df2bbadafaa7d6278aea7`. No IPL decryption, padding changes, or other member transformation was needed. Comparison evidence: `.work/ipl-match/report.json`.
- OFW updater originals and separately classified archive artifacts are under `<backup-root>/ofw-updaters/`. The manifest distinguishes public updaters, UMD-only releases, reconstructed archive containers, factory material, non-retail mislabels, and unresolved source claims. The 6.60/6.61 standard and Go updater bytes were also matched against live Sony endpoints; this is separate from general archive hash verification.
- The acquired collection contains 63 public updater PBPs (51 standard release labels, 10 Go releases, plus same-version revisions), with all four UMD-only release folders recovered against published component hashes. Including separately classified archive material and recovered UMD components/candidates, 197 payload files occupy 2,793,776,259 bytes; all recorded SHA-256 values and lengths were independently checked. Original disc-variant coverage remains partial: 36 of 45 known/locally observed UMD folders are complete, eight are partial, and 3.80 is entirely missing. The 15 missing component associations and the disputed additional 4.00 hash claim are explicit in the manifest; additional original UMD sources are needed for those gaps.
- A separate Sony-only download run is recorded in `<backup-root>/sony-updaters/manifest.json`. Of 63 public updater artifacts, four were acquired directly from live Sony servers: 6.60 and 6.61, each for standard PSP and PSP Go (121,340,356 bytes total). All four were independently checked for expected SHA-256, MD5, size, and bounded PBP sections. The remaining 59 were not acquired; the manifest retains historical-URL evidence, labeled reconstructed candidates, and all 694 attempts. Failure at tested endpoints is not proof of global unavailability. Successful downloads used Sony's original HTTP URLs; Sony cryptographic signatures were not authenticated. No mirror payloads were substituted, and the existing archive collection was left intact.
- Zig-PSP `zNANDTool NAND.bin --idstorage` prints the physical index mapping and complete 512-byte leaves. The PSP-1000 dump yielded 126 plaintext keys; the 64 MiB dump yielded 131 keys when its console's fuse ID was supplied through `--fuse-id HEX`. Every printed leaf exactly matched its independently decoded `inspection/idstorage.zip` counterpart. Missing/wrong fuse IDs were also exercised: exit status 2, raw-index diagnostics, and no invented leaf mappings. Raw dumps and existing derivatives were not modified.
