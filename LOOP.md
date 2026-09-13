# PSPDB overnight improvement loop

Work autonomously on improving the existing PSPDB code during this overnight session. Prioritize native Linux extraction, in-memory data flow, a simpler architecture, and clear, consistent Zig matching the user's projects. Deliver working cutovers and verified simplifications, not just an audit or a growing backlog. Coverage expansion and bulk acquisition are not this session's goal.

## Goal and invariants

PSPDB answers: **which exact bytes occur at which path, in which observed source, and through which extraction steps?** It is a file-provenance catalog, not merely a title list or download manager.

Preserve these boundaries:
- Original source identity, observed inventories, derived outputs, external reference metadata, and optional stored bytes are distinct.
- SHA-256 plus size identifies bytes; filenames, titles and serials do not. Preserve conflicting reference/observed metadata rather than silently reconciling it.
- Sources are read-only. Extracted/decrypted/reconstructed bytes are derivatives, not replacements for original evidence.
- Catalog results are immutable within an extractor revision. Bump only affected revisions when output semantics change; preserve historical pairs. Schema versions are separate.
- Context-dependent extractions must retain their dependencies and occurrence scope. Do not introduce hash-only reuse where sibling/container context changes the result.
- A root is accepted only after its supported descendant extraction jobs succeed. Do not turn errors into silent partial success to increase counts.
- Unknown coverage, unavailable sources, missing metadata, successful decoding, exact hash matches and verified completeness are different states.

## Grounding and available sources

Start with repository instructions, README.md, CONTRIBUTING.md, the current source/tests, and `~/.config/llm/README.md`. The central knowledge base is `~/obsidian/llm/`; PSPDB starts at `project/pspdb/README.md`. Read relevant linked notes before revisiting an experiment. Historical notes can contradict newer implementations: establish what is current and retain evidence for corrections.

Study the user's read-only style references before restructuring Zig: `~/dev/sudoku-zig/src/sudoku/{board,save_state,game}.zig` and `~/dev/p1e/src/{main,psx/state,psx/save_state}.zig`, plus the relevant domain subdirectories. Concrete conventions and limits are specified below. These are style references, not permission to edit those projects or copy their older Zig APIs.

Machine-specific source locations supplied by the user:
- UMD games: `~/nas/torrent/Redump - Sony PSP/`. Use completed archives; ignore `.part` files and do not interfere with active downloads.
- UMD videos: `~/nas/torrent/psp-umd-archive-collection/` (`.iso` and `.ISO`).
- PSN packages: public Sony Zeus package URLs from the PSP/PSX TSV sources. Downloads for this work are authorized; do not guess URLs or require private credentials.
- Existing TSV snapshots: `.work/nopaystation/manual-2026-09-12/` and `~/download`; consult the knowledge-base `nopaystation` note. Scope is PSP and PSX, not Vita/PS3/PSM. Duplicate snapshots and distinct PSX exports exist; filenames do not prove published/pending status.

Discover available scratch capacity from project notes/runtime configuration. Keep the optional content store disabled for this session's performance work; do not rebuild or populate it. Do not assume older mount paths or service settings still apply. Never put machine-local paths, credentials, RAP/zRIF material, source images or stored payloads into public catalog contributions.

## Persistent, ranked work queue

Maintain a concise resumable queue in `.work/overnight/queue.md` and machine-readable experiment/acquisition state where useful. Keep durable conclusions in the central knowledge base, not a new documentation hierarchy in the repository. Do not edit this prompt into a running log.

Each queue item needs: problem/opportunity, evidence, expected impact, priority, confidence, next concrete action, acceptance check, and state (queued/active/blocked/done). Record blockers precisely. Include simplifications in this same queue, not a separate cleanup wish list. Update existing items instead of duplicating them.

Rank by correctness and impact before convenience:
1. **P0:** source/store/catalog corruption, false identity or verification claims, destructive behavior, serious security exposure.
2. **P1:** correctness failures in supported extraction; **port the Wine-dependent PSXtract-2 path to native Linux**; **move EDAT extraction to an in-memory API**; architectural cleanup needed to make these paths direct, understandable and maintainable.
3. **P2:** migrate other existing extractors to memory where practical; simplify ownership, dispatch, provenance and I/O boundaries; normalize Zig structure/style; evidence-backed throughput and memory improvements.
4. **P3:** unrelated ergonomics, new format coverage, acquisition expansion and speculative capabilities. Do not let these displace the implementation priorities above.

Architecture and readability are first-class deliverables, not leftover cosmetic work. Prefer coherent simplifications with explicit before/after responsibilities and verifiable behavior. Investigate only to resolve a concrete implementation question. Do not prioritize easy test-count increases or catalog-count inflation.

## Repeat this cycle

1. Reconcile the queue with the working tree and prior session state. Preserve unrelated user changes. Establish a baseline once; do not repeatedly audit unchanged code or rerun known failures merely to reconfirm them.
2. Inspect a focused path or run a bounded real-input experiment. Capture the failing input identity, command, output and relevant environment/provenance. Distinguish a confirmed defect from a hypothesis.
3. Rank new findings, including opportunities to delete duplication, obsolete paths, redundant state, unnecessary allocations or brittle special cases.
4. Select the highest-impact actionable item. Fix the cause with existing patterns and upstream libraries where appropriate. Architectural refactoring is explicitly in scope: remove accidental complexity, but do not replace it with speculative frameworks, compatibility layers or generic plugin machinery.
5. Verify the changed observable behavior. For bugs, show the reproduction no longer fails; retain a regression test only when it protects a plausible failure. Exercise actual CLI/UI surfaces where changed. Run shared validation after concurrent edits settle, not in each worker.
6. Record the result and proof, update relevant usage docs and knowledge-base conclusions, and remove only scratch artifacts created by this work that are no longer needed. Preserve useful failing samples and provenance. Commit each completed, verified change to local Git as you go; do not accumulate the whole night's work into one commit.
7. Re-rank and continue implementing. Alternate porting/memory work with meaningful architecture and Zig-style cleanup; each cutover should leave its surrounding code simpler. Research must feed a named implementation decision. Do not spend the night exclusively auditing, downloading, benchmarking, mechanically renaming, or writing plans.

Use agents for genuinely independent investigations and changes, with a hard limit of **four active subagents in parallel across the entire session, including nested delegation**. Queue additional work until a slot is free; do not bypass the cap with nested agents. Give each agent explicit scope, file ownership, shared contracts and acceptance criteria. Keep the main agent as integration owner: review results, run shared validation after concurrent edits settle, and serialize staging/commits. Workers must not independently commit shared-worktree changes. Avoid concurrent heavy ingest jobs competing for the same NAS, memory or catalog. Stop or redirect an experiment that is no longer producing useful evidence.

## Primary implementation tracks

### High priority: replace Wine with native Linux PSX extraction

The current PSX path invokes `psxtract.exe` (PSXtract-2) through Wine from `tools/extract_external.py::extract_psx`. Port the actual supported functionality to Linux, not just the launcher.
- Locate the existing upstream sources, build helpers, patches, runtime assets and exact known-good samples before choosing the smallest sound port. Identify Windows-specific APIs, executable dependencies and audio/sector reconstruction behavior. Preserve upstream attribution and licensing.
- Prefer a native build of proven extraction code with narrow portability changes over a fresh decoder or crypto rewrite. A native CLI is a valid first completed cutover; a callable library/in-memory boundary is preferred where practical. A Wine wrapper, renamed executable or incomplete replacement is not a Linux port.
- Preserve whole-PBP context, single/multi-disc behavior, source-backed auxiliary outputs, decoded audio and reconstructed sector bytes for currently supported cases. Distinguish existing upstream limitations from port regressions. Do not drop difficult outputs or silently narrow supported coverage.
- Use the existing Wine path as a differential oracle during development. Compare output paths, sizes and SHA-256 values on representative real inputs, including available audio and multi-disc cases. Exercise recursive ingestion and error behavior; retain the established distinction between reconstructed images and original media.
- Cut production over fully once verified: remove Wine invocation/configuration and obsolete builders/adapters/docs for this path, update tool provenance and freshness handling, and record reproducible Linux build instructions. Keep useful old samples/oracle assets in scratch until comparison is finished; do not indiscriminately delete shared Wine directories.
- If an essential dependency cannot be ported with available information, document the exact unsupported API/codec and attempted approach, finish independently usable work, and continue EDAT/architecture work. Do not label a partial port complete.

### High priority: EDAT uses in-memory inputs and outputs

Move the existing EDAT decoding operation into the ingestion memory pipeline. Input bytes already held by Zig must not be written/reopened through CAS simply to call a helper.
- Inspect `tools/extract_external.py::extract_edat`, the EDAT builder/upstream implementation and the current native decoder/ownership patterns. Reuse proven cryptographic code through a narrow native interface where appropriate; do not invent new crypto or change the format.
- Accept bounded input bytes and explicit required key/context data; return owned plaintext bytes or emit bounded in-memory views using the existing ownership model. A temporary file, RAM-disk path or subprocess accepting a pathname is not this cutover.
- Keep parsing/decryption independent of filesystem access, environment lookup, Python subprocesses, manifests and catalog/store publication. Resolve key acquisition at the boundary; never embed private RAP/key material in code, logs, public metadata or fixtures.
- Preserve supported EDAT variants, length/overflow limits, authentication/integrity checks, missing/wrong-key behavior and source identity. Preserve EDAT/DOCUMENT companion dependencies where applicable; memory-only transport must not erase context.
- Differentially compare plaintext hashes and recursive output trees with the current helper on real supported samples. Verify malformed/truncated/authentication-failing inputs do not publish successful output, and exercise the actual ingest path without the former helper installed.
- Remove the obsolete EDAT subprocess/temporary-output/manifest route and its exclusive dependencies after verification. Update native provenance, revision/freshness handling and documentation; keep only code shared by still-external extractors.

### Move other existing extractors into memory where practical

After the high-priority paths, assess PSAR, RCO, NPUMDIMG, POPS and DOCUMENT by avoidable I/O/process cost, implementation risk and maintainability. Existing native decoders are the pattern, not a reason to create a second architecture.
- Prefer borrowed immutable input views and explicit owned output buffers; use bounded streaming/emission where whole-output allocation would increase peak memory unnecessarily. Clearly document lifetimes and allocator responsibility.
- Keep decoder logic separate from scheduling, filesystem traversal, key discovery, hashing, CAS publication and catalog serialization. Reuse existing byte-owner and inventory boundaries, simplifying them when demonstrably overcomplicated.
- A thin C/C++ library bridge is acceptable when it preserves proven algorithms. Do not rewrite working upstream code in Zig merely for language uniformity. Where a helper must remain file-based, isolate that boundary and state the actual limitation rather than calling it in-memory.
- Benchmark the affected real path before/after under the fast, store-disabled policy below, including wall time and peak memory. Verify byte-equivalent outputs and failure semantics. Fewer subprocesses/files and simpler ownership are useful outcomes; report measured results honestly.

### Speed improvements with fast, store-disabled benchmarks

Improve parsing, decryption, decompression, hashing, memory ownership, allocation/copy cost and dispatch overhead in the current extraction pipeline. **Ignore content-store performance for now; the user will enable the store later.** Do not optimize CAS verification, publication, fsync, directory layout or NAS store traffic during this session. Preserve existing store correctness without making it the subject of new work.
- Each performance experiment uses **at most one representative PKG or ISO**, selected for the changed extractor/path. Do not rerun the five-image suite, build a benchmark matrix or run long soak tests. Use an extracted payload directly for focused decoder measurements when that is faster.
- Keep the feedback loop short: choose the smallest real sample that exercises the change, normally one baseline and one candidate run. Target seconds rather than minutes. Use a short explicit timeout; if the sample is too slow, switch to a smaller representative source or bounded decoder workload, not repeated long runs. Repeat only to resolve a concrete noisy result.
- Run without `--store`, with identical extraction scope and a fresh scratch catalog when applicable; do not use `--skip-existing` to make timings look faster. Report source identity/size, command, build mode, worker count, elapsed time, CPU time and peak memory. Compare output bytes/hashes and acceptance/error behavior, not merely exit speed.
- Store-disabled must not mean silently skipping supported recursive extraction. If the current CLI couples extraction to a store, decouple the required input/context transport as part of the in-memory architecture work; until that is complete, benchmark the actual decoder directly and state the end-to-end limitation. Do not enable a scratch CAS as a workaround for this policy.
- Keep performance experiments separate from correctness coverage: ports still need representative variant/error checks, but those are bounded targeted checks, not multi-image throughput runs. A one-source benchmark cannot establish multi-source intake scaling; leave the established intake cap alone unless a correctness defect requires action.
- Retain only demonstrated speed/resource improvements or independently justified simplifications. Do not claim historical store-enabled timings as the baseline for store-disabled extraction.

### Architecture simplification and consistent Zig

Treat readability and structural cleanup as substantial work throughout the session. Aim for code the user can read top-to-bottom and understand without chasing adapters or hidden ownership.
- Follow the reference projects' domain-oriented files and directories: cohesive state/types, execution/operations and serialization where these are genuinely distinct responsibilities. Split oversized mixed-responsibility modules at real boundaries, not into one-function files; avoid dumping grounds named `utils`, generic managers and unnecessary wrapper layers.
- Group imports at the top by standard library, local domain and external dependencies; use clear local aliases. Keep related constants/types together, struct fields before methods, and tests near the behavior they defend.
- Use the references' **snake_case** for project-owned functions, methods, fields and variables, **PascalCase** for types, and descriptive domain names. Normalize complete touched modules and all their callers, not isolated declarations that leave two styles side by side. Preserve required Zig/FFI hooks and external API spelling. Use symbol-aware rename when available; do not add old-name aliases.
- Prefer explicit state parameters, visible allocators/ownership, small domain structs, direct loops and switches, early error returns, and `defer`/`errdefer` adjacent to resource acquisition. `Self = @This()` is useful inside substantial structs; do not add it mechanically everywhere.
- Make control flow visually readable: expand dense multi-action one-liners, nested conditionals and long mixed-purpose expressions; give meaningful steps names and whitespace. Keep trivial guards concise. Use `zig fmt`, but recognize that formatting alone does not fix compressed or poorly factored code.
- Separate pure parsing/decryption from side effects. Remove duplicated parsing/validation, repeated hashing/copying where safely redundant, redundant state, obsolete paths and adapters whose only role is forwarding. Preserve checks at trust boundaries; simplification is not weakening integrity.
- Keep public surfaces small and ownership/error contracts explicit. Do not introduce abstraction merely to unify unlike formats; a straightforward switch and concrete decoder functions are often clearer than a configurable framework.
- Copy the references' structural clarity, not incidental defects, old APIs, TODOs or verbose comments. Use current Zig 0.16 APIs. Comments should explain invariants, format constraints and non-obvious decisions, not narrate syntax.
- Keep behavior-preserving refactors distinguishable from semantic changes in commits and verification. Demonstrate unchanged catalog bytes for refactors; any intended extraction/provenance change requires the appropriate revision treatment, never a cosmetic revision bump.

### Scope and acceptance

Use already acquired samples first. Bounded acquisition is permitted only to fill a concrete port/decoder verification gap; do not restart broad TSV ingestion, firmware-completeness research or new-container discovery. Game-specific formats remain out of scope. PSMF/MPEGPS remain intentionally removed.

A completed port/memory migration must work end-to-end without its replaced runtime path. A completed architectural cleanup must remove concrete complexity, migrate callers, preserve observable behavior and leave one consistent design. Keep deterministic regression tests for plausible integrity, ownership, context and concurrency failures; use throwaway smoke scripts for straightforward wiring. Report removed dependencies/I/O boundaries, clarified responsibilities, measured resource changes and exact verification—not lines changed or test counts as proxies for quality.

## Restart baseline — 2026-09-13

These decisions and measurements supersede older queue entries and historical knowledge-base notes. Reconcile existing work rather than restoring removed functionality or repeating rejected experiments.

### Current state and deliberate exclusions

- The user deleted the main catalog and content store today. Older inventory counts, freshness reports and validation totals are historical, not a live baseline. Discover the intended main paths and current capacity before rebuilding; do not mistake isolated benchmark catalogs/store for the main dataset.
- **PSMF/PMF and raw MPEG program streams are intentionally opaque.** PSMF and MPEGPS detection/adapters, helper builders/patches, registry entries, contextual integration and the media-only `ijson` dependency were removed at the user's request. Do not restore them or rank them as missing coverage. Movie bytes still receive ordinary file hashes/storage, but no movie extraction subtrees. The earlier public PSMF subtree deletion removed 684 record/tree pairs; no public MPEGPS namespace existed then.
- Native in-memory extraction covers ISO/ISO9660, PKG, PBP, SCE, ELF, VMP, PRX, gzip and KL3E/KL4E. PSAR, RCO, NPUMDIMG, EDAT, POPS, PSX and DOCUMENT use external file-based helpers: CAS source path → temporary outputs → Zig-owned memory → hash/store. PBP PS1 contextual extraction invokes external helpers.
- Embedded Python bootstrap now includes `rap.py`; embedded catalog freshness receives contextual-extractor JSON explicitly rather than relying on `__file__`. Preserve these fixes.
- The user explicitly deferred mmap-versus-owned-buffer exploration. Leave ISO/PKG mapping unchanged; do not resume that experiment without a new request. Repeated mapped accesses do not automatically imply repeated NAS reads.

### Ingestion performance: measured, not inferred from thread count

- ISO/PKG intake now permits **`max(1, configured_threads / 4)`**, rounded down before reserving a progress thread. Eight threads allow two intakes; 32 allow eight. The gate covers whole-source hashing, metadata parsing and the immediate file walk, including ZIP members. Nested extraction retains scheduling priority in the shared worker pool.
- Historical store behavior: a populated store saves writes, not full existing-object verification reads. `Inventory.emitView()` synchronously verifies existing CAS bytes before enqueueing nested extraction. This explained earlier profiling questions, but **store optimization is now deferred**. Preserve corruption detection; do not pursue this path during the current loop.
- Five original NAS ISOs total **7,480,213,504 bytes (6.97 GiB)**: LocoRoco 2 EU; SOCOM Fireteam Bravo 3 Europe PSN; Metal Gear Solid Peace Walker Europe v1.01; Manhunt 2 Europe v1.02 PSN; NFS Most Wanted 5-1-0 Europe PSN.
- Initial post-media-removal benchmark ran those sources separately/sequentially, eight workers, fresh catalogs: initially empty shared store **1069.34s / 6.67 MiB/s**, populated repeat **252.54s / 28.25 MiB/s**. All ten invocations passed; 520 JSON files across the per-source catalogs were byte-identical between passes. Peace Walker now succeeds; its prior failure was the removed PSMF helper's 16 MiB manifest limit.
- The controlled intake comparison instead submits **all five together**, eight workers, populated store, fresh combined catalog each run, ReleaseSafe binaries. Order: one intake → two → two → one. One-intake times **186.34s, 180.09s**; two-intake times **156.02s, 165.22s**. Means: **183.22s / 38.94 MiB/s → 160.62s / 44.41 MiB/s**: **12.3% less elapsed time, 14.1% more throughput**. Peak single-process RSS increased **2.83 → 4.67 GiB**; mean CPU time including waited-for children stayed **37.09 → 35.94s**. All four runs accepted five sources with zero errors; all 480 combined-catalog JSON files were byte-identical across binaries. Shared descendants account for the lower combined-catalog count.
- Throughput above is input bytes divided by elapsed time, **not measured NAS traffic**. OS caches were not flushed and NAS load was uncontrolled. Low CPU consumption establishes waiting dominates, not which network/filesystem/server operation causes it. Two runs per variant support the observed improvement, not a universal performance guarantee. Older media-enabled runs are not equivalent-work comparisons.
- An earlier 64 KiB → 1 MiB verification-buffer trial gave a noisy ~3.7% improvement across four successful sources, with one regression; it was **reverted**. Do not present it as a retained optimization. No hash-library rewrite was retained.

### Evidence, verification and next useful work

- Evidence root: `.work/ingest-speed-five-20260913/`. Individual runs: `{empty-store,populated-store}-20260913-214256/results.json` and `verification-20260913-214256.json`. Intake comparison: `intake-comparison-20260913-222024/{results,verification}.json`, `run.py`, frozen old/new binaries and per-run logs/catalogs. Config files retain exact source paths, sizes, mtimes and helper paths.
- Isolated benchmark store: `/mnt/nas/dev/pspdb-bench-20260913-214256/store`; sibling `inputs/` contains benchmark hardlinks. Preserve these reproducibility assets unless intentionally retiring the experiment; originals and the main catalog/store were not modified by the benchmark.
- Verification already completed: native tests and ReleaseSafe build; intake scheduling regression exercises cap saturation, child/discovery priority and reopening capacity. CLI smoke runs at 1, 3, 8 and 32 threads accepted six generated ISOs each, zero errors. Movie-opacity/catalog-status checks passed 20 tests; earlier tools suite passed 63 tests with one skip and website suite passed 28. These are dated results, not a claim that all suites have run against future changes.
- Known validator mismatch observed before the user's catalog deletion: `tools/validate_catalog.py` requires an external executable hash for PRX, but native PRX v4 records legitimately use `pspdb-ingest` provenance without one. Fix the validator's native/external distinction if still present; do not fabricate executable hashes or rewrite valid records.
- Current performance direction supersedes the historical five-input experiment: use at most one PKG/ISO, store disabled, and short targeted before/after measurements. Focus on extractor computation, allocations/copies and unnecessary process/file boundaries; do not repeat multi-source throughput or store-I/O profiling.
- Root `--skip-existing` checks catalog freshness, not stored-object health; intermediate reuse verifies child bytes. Integrity/repair workflow research is deferred with store performance work, not a task for this session.
- Reconstructed PS1 raw CD BINs remain leaves; exact Redump matches exist for only some outputs. Further filesystem/track inventory remains an exploration candidate, not permission to reinterpret reconstructed bytes as original media.

## Operational limits and stopping

Keep work local. Do not push, deploy, expose a service beyond its existing bind address, install system packages, change torrent configuration, remove historical catalog entries, delete source data, or touch unrelated files. Do not indiscriminately clean `.work`: existing Wine/helper/runtime assets may depend on it. Changes requiring additional approval become blocked queue items; continue with safe work.

Local Git commits are explicitly authorized and expected throughout the night. Prefer small, coherent commits with descriptive messages and verification evidence recorded in the queue. Stage only the intended files; preserve unrelated user edits and staged work. Commit useful verified fixes, simplifications, integrations and validated catalog additions without waiting for a perfect final design—we can prune tomorrow. Keep failed experiments and incomplete changes out of commits represented as working fixes. Do not push, amend existing commits, reset, rebase or squash history during the overnight run. Include commit hashes in the handoff.

At the start of this run, commit the current user-requested working-tree changes as a separate baseline before making new implementation edits. Preserve their actual verification status; do not claim historical checks cover new work. Thereafter commit each coherent verified improvement as it completes, not only at the final handoff.

Use staging catalogs for experiments. Incorporate only validated results into the main catalog, preserving append-only history. Do not let one malformed source monopolize the run: retain its evidence, classify the failure, and continue independent work.

Continue while the overnight session is active and valuable safe work remains. Honor an explicit stop/deadline; do not invent a scheduler, sleep indefinitely, or launch unmanaged background loops to keep the session alive. At a deadline, stop admitting new work, finish or safely terminate active operations, preserve resumable state, and leave no half-applied change presented as complete.

At handoff report briefly:
- Verified fixes and simplifications, with affected files and proof.
- Native Linux and in-memory cutovers, removed runtime/file-I/O dependencies, and any precisely bounded remaining external paths.
- Architecture/style improvements, preserved output equivalence, measured performance/memory changes, rejected approaches and remaining uncertainty.
- Exact validation run and any remaining failures; do not claim unrun checks passed.
- Ranked next actions and blockers; paths to resumable state and durable notes.
- Any processes intentionally left running and how to stop them.

No findings is acceptable only with evidence of the focused checks performed. A large backlog without completed, verified work is not the goal.
