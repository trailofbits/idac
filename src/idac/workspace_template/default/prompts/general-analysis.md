# General Analysis

Use this for a light reverse-engineering pass or one incremental cleanup.

## Setup

- **Context**: <!-- -c db:/path/to/file.i64, -c pid:1234, or blank to use AGENTS.md default -->
- **Target**: <!-- symbol, function, type, class, or family under analysis -->
- **Scope**: <!-- exact boundary for this pass -->
- **Objective**: <!-- what should become more readable or better evidenced -->
- **Prior work**: <!-- audit entry, recovered header, artifact path, or "none" -->

If any required placeholder is still blank at runtime, ask instead of guessing.

## References

If the idac guide is not already in context, run `idac docs guide` first. Use focused topics as needed:

- `idac docs cli` for command grammar and output behavior
- `idac docs targets` for context/backend selection
- `idac docs workflows` for preview, batch, mutation, reanalysis, and locals selectors
- `idac docs troubleshooting` for socket, backend, stale-result, or mutation failures

## Pass Contract

- Read existing workspace state before changing anything: `AGENTS.md`, relevant `audit/` entries, `headers/recovered/`, and prior artifacts.
- Work from the binary/database first; do external correlation only when the user asks or the task requires it.
- Keep durable notes in `audit/<target>-recovery.md`; use `.idac/tmp/` for transient JSON, decompile, or preview artifacts.
- If you mutate the database or headers, record what changed, what evidence justified it, what failed, and what remains inferred.
- Before any mutation batch, run `idac batch <file> --lint --out .idac/tmp/<name>.lint.json`.
- Use `type check`, `function prototype check`, and `type deps` when parser behavior or type dependencies are part of the risk.

## Audit Entry

Append to `audit/<target>-recovery.md` using `references/templates/checkpoint-note.md` inside this workspace or `idac docs templates`.

## Done When

- Representative readback for the scoped target has been inspected.
- Any committed mutation has been reanalyzed and reread when required by the guide.
- Local cleanup after reanalysis used fresh `function locals list --json` data, stable selectors, or `function locals apply`.
- The audit entry names changed database state, updated headers, uncertainty, failed commands, and next steps.
- The final response summarizes only the material outcome and remaining risk.
