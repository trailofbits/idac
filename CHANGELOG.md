# Changelog

## 0.16.0

This release improves headless `idalib` startup and discovery, expands bulk decompile artifact output, and tightens safety around serialized mutation workflows.

- Added automatic IDA install discovery from the user config and surfaced headless `idalib` targets alongside GUI targets, with clearer health diagnostics for missing licenses, missing installs, and backend startup failures.
- Made `idalib` worker startup more reliable by using an explicit readiness pipe, which avoids guessing when the worker socket is ready and produces better timeout behavior.
- Added optional `decompilemany` disassembly and ctree artifact outputs, documented address lookup behavior, and stabilized generated artifact names.
- Hardened batch execution by requiring explicit output for mutating batch runs and clarifying serialized `idac` usage in the bundled agent/workspace guidance.
- Improved function listing by classifying entries and refining demangled-name filtering, with updated renderers, docs, and coverage.
- Refreshed README and bundled skill guidance for binary workflows, packed-struct recovery, and current backend behavior.

## 0.15.0

This release adds a local docs surface for agent workflows and keeps the bundled workspace reference expectations aligned with the shipped assets.

- Added `idac docs` as a CLI-only command for reading bundled command help, workflow guidance, IDA type references, and workspace resource indexes without requiring a live IDA target.
- Grouped the docs index around operation help, IDA references, workflows, and workspace resources so agents can find the right guidance without scanning raw bundled files.
- Updated bundled skill and CLI reference guidance to point agents at `idac docs` for focused help, and raised the inline docs output limit for single-topic reads.
- Synced workspace-init CLI coverage with the complete bundled reference set, including the advanced IDA type annotation and SetType reference files.

## 0.14.0

This release broadens search and inspection ergonomics, hardens artifact and preview behavior, and refreshes the bundled workflows used for agent-driven reversing passes.

- Added segment-scoped search support across byte, string, function, and prototype/comment inspection flows, including runtime segment resolution and tests for both CLI request builders and `idalib` execution.
- Improved command ergonomics with root-level context forwarding, local retype shorthand, clearer agent-oriented help output, and more consistent `cli2` argument normalization across batch, preview, function, search, type, database, and top-level commands.
- Hardened output artifact handling so `--out` writes fail more predictably, report artifact paths consistently, and avoid partial or ambiguous output behavior in batch and serialized result flows.
- Added packaged workflow templates for prototype, rename, checkpoint, and locals/jq passes, then updated README, docs, skill references, and workspace prompts to match the current command surface.
- Refined operation helpers, preview registration, renderer dispatch, class/type regression handling, bookmark/comment/prototype/database family behavior, and GUI transport status metadata.
- Expanded and reorganized coverage around CLI parsing, operation dispatch, output limits, comments atomicity, installers, bundled assets, byte/string search, `idalib` backend behavior, and class/type/local/prototype regression cases.

## 0.13.0

This release sharpens search behavior, hardens a few transport edges, and keeps the bundled agent guidance aligned with the current public CLI.

- Added regex matching support to list-style flows and moved string discovery onto the public `search` surface so text-heavy exploration paths are easier to use consistently.
- Tightened a couple of reliability edges around bounded search execution and GUI bridge process behavior, including explicit timeout requirements and SIGPIPE handling with follow-on coverage.
- Refreshed the markdown prompts and workflow docs so the bundled guidance tracks the command surface that actually ships.

## 0.12.0

This release improves several IDA-facing helpers, tightens a few mutation paths, and aligns coverage with the current public CLI contract.

- Expanded shared runtime and search helper behavior so xref-heavy lookups and related helper flows expose richer structured information with better direct test coverage.
- Refined prototype and bookmark mutation plumbing around the underlying IDA APIs, including follow-on CLI and bridge adjustments for those workflows.
- Synced the workspace-init and comment-preview/readback tests with the current scaffold contents and the newer comment result shape.

## 0.11.3

This release is a small polish pass on the bundled agent guidance and workspace scaffolding.

- Simplified the bundled `idac` usage examples so agents stop overusing explicit `-c db:...` locators in routine command snippets, and normalized example quoting for identifiers, paths, local IDs, and declaration strings.
- Added a workspace template prompt for class-recovery passes so generated reversing workspaces include a ready-made recovery checklist, command sequence, and audit-log structure.

## 0.11.2

This release tightens a few high-friction CLI edges and updates the bundled recovery guidance to match the command surface that actually ships.

- Improved `type declare` import ergonomics by stripping comment and preprocessor noise before handing declarations to IDA, which makes guarded headers and comment-heavy recovery drafts less fragile.
- Fixed several bundled class-recovery references and agent prompts so they stop pointing at the non-public `type vtable dump` path and instead steer recovery work toward the current `type class` workflow.
- Included the recent CLI polish around selector parsing, `--out` artifact notices, and workspace-init output cleanup in the release line.

## 0.11.0

This release continues the CLI/ops cleanup, improves diagnostics around mutation flows, and adds a first-class workspace bootstrap path with local reference docs for agent-driven reversing.

- Refined the rewritten `cli2` surface with cleaner request builders, more direct argparse handling, and better normalization around complex command arguments and local-variable update flows.
- Improved failure reporting and coverage around batch execution, locals handling, and related operation-manifest wiring so mutation-heavy workflows are easier to diagnose when they go wrong.
- Added `workspace init` scaffolding docs and behavior, including copying the bundled skill reference markdown into a workspace-local `reference/` directory and updating the generated agent guidance to point at the right class-recovery and C++ vtable/type references.

## 0.10.0

This release completes the move onto typed operation families, tightens the transport story around the Unix socket backends, and updates the docs to match how the tool actually behaves now.

- Reworked the operation layer around typed command families, a clearer manifest and dispatch path, and thinner compatibility shims, which makes follow-on command work easier to reason about and extend.
- Continued the operations cleanup across runtime helpers, dispatch wiring, and surrounding command plumbing so the rewritten command surface behaves more coherently end to end.
- Updated the docs, skill guidance, and agent prompts to match the current CLI and Unix socket behavior, including clearer preview guidance and explicit `--no-cache` decompile advice for type-recovery passes.

## 0.9.0

This release ships the rewritten CLI parser, tightens the command language around it, and makes the overall command surface feel much more deliberately consistent.

- Rebuilt the CLI parser around the new command-routing path so target discovery, subgroup resolution, and help fallback behave like one coherent system instead of a pile of edge cases.
- Pushed the command rewrite further across the tree so related operations use even more consistent family names, argument shapes, and help text, reducing the amount of command-specific trivia you need to remember.
- Simplified execution and error flow around the new parser, which makes the CLI feel sharper during normal use and gives follow-on command work a cleaner foundation.

## 0.8.1

This release sharpens command routing, improves fresh decompile workflows, and makes backend timeouts easier to reason about.

- Refactored CLI context selection so commands resolve targets and backends more consistently, with docs and skill guidance updated to match the newer command surface.
- Added fresh decompile controls, including the new `--f5` alias for `--no-cache`, plus demangled lookup support to make one-off pseudocode refreshes and symbol lookup less awkward.
- Renamed the batch Python execution surface to the new subcommand names and tightened help output so incomplete commands show subgroup guidance instead of falling back to generic top-level help.
- Improved transport timeout handling across the GUI bridge and `idalib`, including serialized GUI bridge dispatch so requests run one-at-a-time on the main thread, with stronger tests around timeout behavior and request/response edge cases.

## 0.7.0

This release simplifies the CLI taxonomy, standardizes several command families, and adds a small layer of human-friendly shorthand.

- Refactored the command tree around canonical families such as `database`, `function locals`, `function proto`, `type class`, `type struct`, `type enum`, and top-level `rename`, removing older duplicate surfaces and moving target discovery under `doctor`.
- Standardized several command names and argument shapes, including `database show`, `bookmark list/show`, `comment show`, positional comment text, `function proto show`, `database save [path]`, and `type declare --decl-file`.
- Moved installer flows under `misc` as `misc plugin install` and `misc skill install`, and updated the docs and skill references to match the new command surface.
- Improved bulk and batch ergonomics with decompile path-length safeguards, per-step batch output artifacts, stricter batch output validation, and short aliases for common flags such as `-j`, `-o`, `-q`, and `-p`.

## 0.6.0

This release improves class-recovery workflow quality and removes duplicated packaged asset trees from the repo.

- Tightened class-recovery ergonomics with better raw-vtable boundary handling, normalized type-size reporting, clearer non-materialized-class hints, and stronger guidance around preview, caller reanalysis, broad decompile capture, and `batch apply`.
- Consolidated packaged workspace and IDA plugin assets into single canonical locations under `src/idac`, removing the old duplicate checkout and `_bundled` copies.
- Updated installer, path-resolution, and asset tests to match the new packaged layout.

## 0.5.2

This release overhauls the skill's content architecture for progressive disclosure and rewrites the README.

- Restructured the skill around content ownership: SKILL.md carries only safety-critical rules and routing, while reference files own detailed workflows, class recovery procedures, and command catalogs. Eliminated duplication across files.
- Rewrote the README with a quick start at the top, a compact command families table, and development internals moved to docs/development.md.
- Fixed a bridge plugin parity issue and improved bundled asset and path test coverage.

## 0.5.1

This release improves class-recovery ergonomics, preview safety, and failure diagnostics for day-to-day RE passes.

- Added `type class candidates --kind ...` so you can filter mixed family discovery results down to functions, vtables, RTTI, or local types without post-processing a broad result set.
- Added `type declare --bisect` / `--diagnose` style failure isolation for recovered headers, including better hints for opaque by-value support-type blockers during class import work.
- Expanded preview workflows: `function proto set --preview-decompile` now returns best-effort decompile readback, and local rename/retype previews can return a compact diff instead of full before/after local lists.
- Added stronger live-GUI mutation guardrails by failing fast when another mutation is already active on the same target, including preview mutations.
- Improved class-materialization guidance when a type exists only as an opaque local type, with clearer recovery hints that push users toward `type show`, `type class candidates`, and recovered header import.
- Tightened large-output and discovery behavior around `type list`: the command now requires either an explicit pattern or `--out`, and the docs now call out top-level array JSON outputs and overflow guidance more directly.
- Relaxed `doctor` behavior for live plugin/install drift so an active matching GUI bridge is treated as usable with warnings instead of a hard failure.

## 0.5.0

This release makes `idalib` behave more like a real working session, expands a few core workflows, and simplifies how `idac` ships its agent assets.

- Implemented bookmark commands for listing, adding, setting, and deleting IDA bookmarks from the CLI.
- Added `strings scan` for bounded address-range searches, which complements normal defined-string listing when you need to sweep a region for candidate strings before cleanup or typing work.
- Reworked `idalib` around explicit per-database sessions with `db open`, `db save`, and `db close`, replacing the old temp-copy persistence flow.
- Clarified persistence behavior across the tool, including explicit saves, reusable Python evaluation state with `py eval --persist`, and GUI support for `db save`.
- Cleaned up runtime and packaging behavior by moving transient socket state out of `~/.idapro`, adding stale-runtime cleanup, and consolidating the `idac` skill into one canonical packaged location.

## 0.4.0

This was the first packaged release of `idac` with the GUI bridge and headless `idalib` backends, shared RE command coverage, and installable agent skill support for Claude and Codex.
