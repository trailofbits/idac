# Workspace

This is an idac reverse-engineering workspace.
If the idac guide is not already in context, run `idac docs guide`. Detailed references
live under `references/` and via `idac docs TOPIC`; when command syntax is unclear or
errors, `references/cli.md` (`idac docs cli`) is canonical.

## Structure

- `audit/` — durable notes and findings, one `audit/<target>-recovery.md` per target
- `headers/recovered/` — headers reconstructed from reversing, one `<target>.h` per target
- `headers/vendor/` — reference headers from SDKs or public source
- `references/` — local copies of the bundled idac and IDA reference docs
- `scripts/` — reusable idac/IDA Python scripts
- `prompts/` — the fill-in task prompt (`prompts/recovery-pass.md`)
- `.idac/tmp/` — scratch space for transient output (gitignored)

## Default target

Default target: (none set — ask before assuming one)

Replace the parenthetical above with a context selector such as `db:/path/to/firmware.i64`
or `pid:1234`. A filled-in **Context** value in a task prompt overrides this default; if
both are missing, ask instead of guessing.

## Conventions

- Start each pass from `prompts/recovery-pass.md`. Target, Scope, and Objective are
  required — ask when they are missing.
- Follow the mutation rules in `idac docs workflows` for every database change: preview
  before commit, lint batches before running them, reanalyze and reread after type or
  prototype changes, and calibrate local selectors from fresh locals JSON.
- Record every pass in `audit/<target>-recovery.md` using
  `references/templates/checkpoint-note.md`. Keep entries append-only and factual, and
  distinguish proven facts from inferred names, types, and semantics.
- Use `.idac/tmp/` for large transient `--out` artifacts.
