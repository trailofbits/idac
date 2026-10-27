# Workspace

This is an idac reverse-engineering workspace.
Install the `idac` Agent Plugin through a compatible client before starting a pass; its
skill carries the guide and the detailed command, workflow, and IDA type references.

## Structure

- `audit/` — durable notes and findings, one `audit/<target>-recovery.md` per target
- `headers/recovered/` — headers reconstructed from reversing, one `<target>.h` per target
- `headers/vendor/` — reference headers from SDKs or public source
- `scripts/` — reusable idac/IDA Python scripts
- `prompts/` — the fill-in task prompt (`prompts/recovery-pass.md`)
- `.idac/tmp/` — scratch space for transient output (gitignored)

## Default target

Default target: (none set — ask before assuming one)

Replace the parenthetical above with a context selector such as
`-c /path/to/firmware.i64` or `--instance <record-id>`. A filled-in **Context** value in
a task prompt overrides this default; if both are missing, omit a selector only when
exactly one READY Nexus instance exists. Otherwise ask instead of guessing.

## Conventions

- For Linux per-command sandboxes, launch `idac database open PATH --json` outside
  the sandbox through the client's approved execution mechanism. If the generated
  Codex allow rule is trusted and loaded, invoke that standalone command directly;
  it already has permission to run outside the sandbox. In a separate tool call,
  verify the returned record is READY with `session_status=ready` in `targets list --json`.
  Use `--instance RECORD_ID` for all agents and run `database close --instance RECORD_ID`
  after the shared session finishes. Follow the skill's recovery instructions if
  a command leaves the host in `recovery_required`.
- Start each pass from `prompts/recovery-pass.md`. Target, Scope, and Objective are
  required — ask when they are missing.
- Follow the skill's mutation workflow for database edits. Preview parser-risky
  type/prototype changes and uncertain selectors; confirmed renames, comments, and
  parameter-name edits with `--preserve-cc` can be committed directly with readback.
  Lint mutation batches, reanalyze after meaningful type or prototype changes, and
  calibrate local selectors from fresh locals JSON.
- Record every pass in `audit/<target>-recovery.md` using the skill's checkpoint-note
  skeleton. Keep entries append-only and factual, and distinguish proven facts from
  inferred names, types, and semantics.
- Use `.idac/tmp/` for large transient `--out` artifacts.
