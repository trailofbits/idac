# General Analysis

Use the `$idac` skill for this reverse-engineering task.

## Target

- Work only on this IDA target: `<BACKEND/TARGET OR DATABASE>`
- Scope this pass to: `<class | type | symbol family>`
- Current objective: `<what needs to become readable or recoverable>`

## Working Mode

- Prefer first-class `idac` commands over ad hoc shell guesses or raw IDAPython. Use `py exec` only when no first-class command fits the job.
- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- Use the `idac` command grammar from `reference/cli.md`. List commands take a positional filter, bulk decompiles use `decompilemany`, mutations are previewed via the `preview` wrapper, string discovery lives under `search strings`, and rename/reanalyze/install flows live under `misc`.
- Read the existing workspace state before changing anything: `AGENTS.md`, `audit/`, `headers/recovered/`, and any prior artifacts for this family.
- If C++ class recovery is in scope, review `reference/class-recovery.md` and `reference/ida-cpp-type-details.md` before writing declarations or vtable layouts.
- Keep the pass phased: discovery, read-only audit, mutations, explicit reanalyze, local rename/retype, final readback.
- Unix socket access is required for all live GUI operations (read-only and mutating). If read-only commands succeed but a mutation fails, troubleshoot the underlying IDA/database error rather than assuming a socket permission split.
- Preview supported mutations before committing them with the wrapper form `preview -o <path> <command...>`.
- After meaningful type or prototype changes, run `reanalyze` before more rename-heavy cleanup.
- During type or prototype recovery, run `decompile` and `decompilemany` with `--f5` so each pass reflects the latest imported types and prototype changes. During ordinary exploration and routine readback, `--f5` is usually not necessary.
- For a single large decompile, use `-o/--out` on `decompile`; reserve `--out-file` and `--out-dir` for `decompilemany`.
- Before `function prototype set`, run `function prototype show` to capture the current signature and confirm the intended delta.
- Before batch local renames, run `function locals list --json --out <path>`, prefer `--local-id` or `--index` after reanalysis drift, and stop on the first rename miss to recalibrate.
- For large rename previews, write the preview to disk with `preview -o <path>` and inspect the JSON artifact with `jq` instead of relying on inline output.
- Prefer minimal `struct` declarations first, then grow them from proven offsets and access patterns. Use blob padding for unknown regions instead of guessed scalar fields.
- Treat inferred semantics as provisional. Use neutral offset-based names or `_maybe` suffixes until the evidence is strong.

## Reverse-Engineering Goals

- Read and understand representative decompiled output for the scoped family.
- Recover structs, classes, enums, typedefs, vtables, and support types by using field offsets, field usage, constructors, callers, callees, xrefs, debug strings, defined strings, RTTI, demangled names, and runtime vtable data when available.
- Include adjacent support structs or enums only when they are directly needed to make the scoped family readable.
- Build or refine reusable recovered headers in `headers/recovered/`, favoring one family header per area instead of scattered throwaway declarations.
- Apply recovered headers with `type declare --replace --decl-file ...` when the declarations are strong enough to improve the database.
- Update function prototypes, local variable names, local types, and related support types so the decompiler output becomes materially easier to read.
- Redecompile representative constructors, destructors, overrides, parsers, helpers, and important callers to verify that the changes actually improved output.
- Make one incremental pass that leaves the next agent with a cleaner database and better recorded context.

## Durable Log And Handoff

- Keep an append-only audit trail. Add a new dated section instead of rewriting prior notes.
- Record durable notes in `audit/journal.md` and open questions in `audit/open-questions.md`. Create them if missing.
- For each pass, log the exact target and scope, functions and types reviewed, evidence used for recovered fields and names, mutations attempted, what improved, what failed, tool rough edges, and recommended next steps.
- Keep machine-readable mutation logs, JSON outputs, and decompile dumps in `artifacts/` when present. Use `.idac/tmp/` for transient outputs when they do not need to be kept.
- For larger mutation passes, prefer a saved `recovery.idac` batch file plus its `batch --out` log so future agents can audit the exact mutation order and results.

## Completion Requirements

- Summarize what changed in the database and which headers were updated or applied.
- State what remains uncertain and which names, types, or semantics are still inferred.
- Call out failed commands, parser limitations, or places where `idac` workflow and tooling could be improved.
- Leave the workspace in a state where another agent can continue incrementally without redoing discovery from scratch.
