# PSPDB overnight improvement loop

Work autonomously on PSPDB for this overnight session. Deliver verified improvements, not just an audit or a growing backlog. Alternate fixing concrete problems with investigating high-value ways to expand coverage. Keep the implementation lean.

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

Machine-specific source locations supplied by the user:
- UMD games: `~/nas/torrent/Redump - Sony PSP/`. Use completed archives; ignore `.part` files and do not interfere with active downloads.
- UMD videos: `~/nas/torrent/psp-umd-archive-collection/` (`.iso` and `.ISO`).
- PSN packages: public Sony Zeus package URLs from the PSP/PSX TSV sources. Downloads for this work are authorized; do not guess URLs or require private credentials.
- Existing TSV snapshots: `.work/nopaystation/manual-2026-09-12/` and `~/download`; consult the knowledge-base `nopaystation` note. Scope is PSP and PSX, not Vita/PS3/PSM. Duplicate snapshots and distinct PSX exports exist; filenames do not prove published/pending status.

Discover the current configured store and available scratch capacity from project notes/runtime configuration. Do not assume older mount paths or service settings still apply. Never put machine-local paths, credentials, RAP/zRIF material, source images or stored payloads into public catalog contributions.

## Persistent, ranked work queue

Maintain a concise resumable queue in `.work/overnight/queue.md` and machine-readable experiment/acquisition state where useful. Keep durable conclusions in the central knowledge base, not a new documentation hierarchy in the repository. Do not edit this prompt into a running log.

Each queue item needs: problem/opportunity, evidence, expected impact, priority, confidence, next concrete action, acceptance check, and state (queued/active/blocked/done). Record blockers precisely. Include simplifications in this same queue, not a separate cleanup wish list. Update existing items instead of duplicating them.

Rank by correctness and impact before convenience:
1. **P0:** source/store/catalog corruption, false identity or verification claims, destructive behavior, serious security exposure.
2. **P1:** ingestion failures affecting supported real inputs, incorrect extraction/reuse/provenance, misleading browser results, blockers affecting many sources.
3. **P2:** evidence-backed coverage expansion, reproducibility, resource/performance improvements, and simplifications that remove meaningful maintenance cost.
4. **P3:** isolated ergonomics, cosmetic issues and speculative capabilities.

Within a priority, prefer broad impact, strong evidence, a small coherent change and a clear verification path. Exploration is valuable when it reduces a named uncertainty or unlocks coverage; do not prioritize easy test-count increases or catalog-count inflation.

## Repeat this cycle

1. Reconcile the queue with the working tree and prior session state. Preserve unrelated user changes. Establish a baseline once; do not repeatedly audit unchanged code or rerun known failures merely to reconfirm them.
2. Inspect a focused path or run a bounded real-input experiment. Capture the failing input identity, command, output and relevant environment/provenance. Distinguish a confirmed defect from a hypothesis.
3. Rank new findings, including opportunities to delete duplication, obsolete paths, redundant state, unnecessary allocations or brittle special cases.
4. Select the highest-impact actionable item. Fix the cause with existing patterns and upstream libraries where appropriate. Avoid speculative frameworks, compatibility layers and broad refactors unrelated to the problem.
5. Verify the changed observable behavior. For bugs, show the reproduction no longer fails; retain a regression test only when it protects a plausible failure. Exercise actual CLI/UI surfaces where changed. Run shared validation after concurrent edits settle, not in each worker.
6. Record the result and proof, update relevant usage docs and knowledge-base conclusions, and remove only scratch artifacts created by this work that are no longer needed. Preserve useful failing samples and provenance. Commit each completed, verified change to local Git as you go; do not accumulate the whole night's work into one commit.
7. Re-rank and continue. Normally spend about two focused implementation cycles per exploration cycle. Override this balance for P0/P1 issues or when research is the prerequisite to a fix. Do not spend the night exclusively auditing, bulk-downloading, polishing, or building speculative infrastructure.

Use agents for genuinely independent investigations and changes, with a hard limit of **four active subagents in parallel across the entire session, including nested delegation**. Queue additional work until a slot is free; do not bypass the cap with nested agents. Give each agent explicit scope, file ownership, shared contracts and acceptance criteria. Keep the main agent as integration owner: review results, run shared validation after concurrent edits settle, and serialize staging/commits. Workers must not independently commit shared-worktree changes. Avoid concurrent heavy ingest jobs competing for the same NAS, memory or catalog. Stop or redirect an experiment that is no longer producing useful evidence.

## Coverage exploration tracks

### Consistent and complete firmware inventories

Investigate how to obtain reproducible stock installed-filesystem inventories across firmware versions and PSP hardware models, not just more PSAR outputs.
- Read existing firmware acquisition/reconstruction notes first. Identify what update packages contain versus what installation generates, transforms, omits or selects by hardware model.
- Define completeness relative to an explicit version, model, partition set and acquisition method. Separate stock files, device-specific data, generated state and CFW modifications.
- Compare feasible sources/methods using existing tools and primary references. Prefer reproducible offline analysis before any physical-device operations.
- Run small experiments that can confirm or reject a method. Record exact inputs, tool revisions, inventories and unresolved differences. Do not call a PSAR extraction a complete installed filesystem.
- The user's ARK-4 PSP is not a stock baseline. Do not flash, reset, modify or acquire private/device-unique material from hardware without explicit approval. If that is required, finish safe research and mark the exact prerequisite blocked.
- Promote a method into production only after its evidence model and representative results are defensible; otherwise deliver a precise research result rather than a fake completeness flag.

### Ingesting TSV-accessible PSP/PSX data

Determine and implement the smallest robust path from the available TSV reference rows to verified package ingestion and measurable coverage.
- Inventory raw snapshots by hash and inspect actual headers. Preserve category, snapshot origin, status when known, and conflicting rows. Deduplicate acquisition without collapsing distinct packages or losing references.
- Account separately for all in-scope rows: already ingested, downloadable, missing URL, unavailable, integrity mismatch, unsupported format, extraction failure, and pending. Missing hashes/sizes are unknown, not verification success or zero.
- Start with representative categories and format edge cases, then expand successful ingestion. PSP games, demos, DLC, themes, updates and PSX may exercise different boundaries.
- Reuse local packages and stored evidence before downloading. Use listed public Sony URLs, bounded concurrency/timeouts, finite retries/backoff, disk-space checks and resumable state. Respect access failures; do not bypass controls or hammer unavailable endpoints.
- Download to clearly incomplete temporary names, validate supplied size/hash when available, identify the actual PKG, and only then admit it for ingestion. Preserve reference-vs-observed disagreements.
- Keep reference import/acquisition separate from observed catalog records. An unavailable row remains accounted for; do not fabricate its inventory. A downloaded PKG is not an ingested PKG, and an ingested PKG is not proof that every possible inner format is supported.
- Define completion against the specific snapshots and reachable sources, not 'all PSN'. Report denominators, unique-package counts and unresolved rows. Build resumability/automation only to serve this concrete workflow, not a general crawler platform.

### Unsupported shared container formats

Research files that contain other files or payloads but currently remain opaque because PSPDB lacks extraction support. PBP illustrates the kind of container to investigate; its existing support is not a reason to reimplement it.
- Focus on platform/system formats and broadly reused standard containers found across PSP/PSX sources. **Do not spend time researching or implementing game-specific formats**, including title-specific archives or engine-specific asset packs.
- Start from observed files and the existing signature detector/extractor registry. Distinguish missing format support from unsupported variants, missing tools, failed extraction, and intentionally opaque payloads.
- Identify candidates using signatures, structural evidence, primary documentation and existing tools—not extensions alone. Record representative source/file hashes, occurrence counts, affected releases, likely contents and any encryption/context dependencies.
- Rank candidates in the shared queue by coverage unlocked, evidence strength, reusable upstream support and implementation/maintenance cost. Prefer a small adapter to a proven extractor over a new parser or codec.
- Run bounded extraction experiments on representative samples before adding production support. Verify output boundaries, original-container preservation, child hashes and recursive dispatch; retain provenance and explicit unsupported cases.
- Deliver either a verified integration using the existing extraction model and revision rules, or an evidence-backed research finding with a concrete next step. Do not turn speculative format identification into a catalog claim.

## Initial evidence worth following up

These are prior-review findings, not an instruction to repeat the whole review or an exhaustive priority order:
- Catalog validation passed at 1,306 pairs / 47 unique ISO images; static export selected 47 ISO and 10 PKG roots. These counts will change.
- Freshness scan reported 182 trees missing current revisions, affecting 47 ISO and 3 PKG roots. Investigate implications and regeneration needs; do not overwrite old results or blindly reingest everything.
- `ingest/tests/test_ingest_cli.py::test_pbp_sce_prx_and_gzip_recurse` expects gzip `strip_suffix`, while `catalog.publishExtraction` emits `decoded_suffix`. Evaluate the consumer contract; do not simply repin an implementation-detail assertion.
- README/contribution PKG examples name revision 4 while the registry was at 5. Some knowledge-base sections describe superseded layouts and extraction support.
- Root `--skip-existing` checks catalog freshness, not stored-object health; intermediate reuse verifies child bytes. Assess whether the intended workflows need a distinct integrity/repair operation before treating this as a bug.
- Reconstructed PS1 raw CD BINs remain leaves; exact Redump matches exist for only some outputs. Further filesystem/track inventory is an exploration candidate, not permission to reinterpret reconstructed bytes as original media.

## Operational limits and stopping

Keep work local. Do not push, deploy, expose a service beyond its existing bind address, install system packages, change torrent configuration, remove historical catalog entries, delete source data, or touch unrelated files. Do not indiscriminately clean `.work`: existing Wine/helper/runtime assets may depend on it. Changes requiring additional approval become blocked queue items; continue with safe work.

Local Git commits are explicitly authorized and expected throughout the night. Prefer small, coherent commits with descriptive messages and verification evidence recorded in the queue. Stage only the intended files; preserve unrelated user edits and staged work. Commit useful verified fixes, simplifications, integrations and validated catalog additions without waiting for a perfect final design—we can prune tomorrow. Keep failed experiments and incomplete changes out of commits represented as working fixes. Do not push, amend existing commits, reset, rebase or squash history during the overnight run. Include commit hashes in the handoff.

Use staging catalogs for experiments. Incorporate only validated results into the main catalog, preserving append-only history. Do not let one malformed source monopolize the run: retain its evidence, classify the failure, and continue independent work.

Continue while the overnight session is active and valuable safe work remains. Honor an explicit stop/deadline; do not invent a scheduler, sleep indefinitely, or launch unmanaged background loops to keep the session alive. At a deadline, stop admitting new work, finish or safely terminate active operations, preserve resumable state, and leave no half-applied change presented as complete.

At handoff report briefly:
- Verified fixes and simplifications, with affected files and proof.
- Coverage gained, with clear source/row/package denominators and failure counts.
- Research conclusions, rejected approaches and remaining uncertainty.
- Exact validation run and any remaining failures; do not claim unrun checks passed.
- Ranked next actions and blockers; paths to resumable state and durable notes.
- Any processes intentionally left running and how to stop them.

No findings is acceptable only with evidence of the focused checks performed. A large backlog without completed, verified work is not the goal.
