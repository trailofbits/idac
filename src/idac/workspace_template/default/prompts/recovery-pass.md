# Recovery Pass

Task prompt for one idac reverse-engineering pass — anything from a read-only look at a
single function to a multi-target type/prototype recovery effort.

## Setup

- **Context**: {{CONTEXT}} (e.g. `-c /path/to/file.i64` or `--instance <record-id>`)
- **Target**: {{TARGET}} (symbol, function, type, class, family, module, or behavior)
- **Scope**: {{SCOPE}} (the exact boundary of this pass: what is in and what is out)
- **Objective**: {{OBJECTIVE}} (what should become readable, typed, or evidenced)
- **Prior work**: {{PRIOR_WORK}} (audit entry, recovered header, artifact path, or "none")

Any value still containing `{{...}}` is unfilled. Target, Scope, and Objective are
required — ask for them instead of guessing. For an unfilled Context, use the
AGENTS.md default target; if none is set, omit a selector only when exactly one
READY Nexus instance exists. Otherwise ask. Prior work defaults to "none".

## References

Install the `idac` Agent Plugin through a compatible client first; its skill loads
focused references for command grammar, the mutation workflow, Nexus context
selection, and runtime troubleshooting.

## Pass contract

- Read the existing workspace state first: `AGENTS.md`, the relevant `audit/` entries,
  and `headers/recovered/`. Extend prior work instead of rediscovering it; if the latest
  audit entry no longer matches the database, note the mismatch and re-verify before
  building on it.
- Follow the skill's mutation workflow for database edits: preview parser-risky
  type/prototype changes and uncertain selectors, and read back committed state.
  Confirmed renames, comments, and parameter-name edits with `--preserve-cc` can
  be committed directly. Lint mutation batches and reanalyze and reread after
  meaningful type or prototype changes.
- Work from the binary/database only. Do external correlation only if the user
  explicitly asks or the task is specifically about external correlation.
- Keep recovered declarations in `headers/recovered/<target>.h` and durable notes in
  `audit/<target>-recovery.md`; write transient JSON, decompile, and preview artifacts
  to `.idac/tmp/`.
- Record what changed, what evidence justified it, what failed, and what remains
  inferred.

## If the scope spans multiple targets

1. Capture the function/type surface with filtered `function list`, `type list`, and
   class-candidate reads.
2. Order the work by dependency: support types before prototypes, base layouts before
   derived layouts, prototypes before local cleanup. Prioritize base types, shared
   support structs, and prototypes that dominate many callers.
3. Record the priority order in `audit/<target>-triage.md`.
4. Work one increment at a time; do not expand into adjacent families unless the
   objective requires it.

## If the target is a C++ class, vtable, or hierarchy

Read the skill's class-recovery reference and follow it; it owns the family-scoping,
vtable-loop, naming, and verification rules. Read its C++ type-details reference before
writing or importing class or vtable declarations.

## Done when

- The stated objective is met and affected state is verified. Use fresh `--f5`
  pseudocode for meaningful type/prototype changes and an affected caller when
  propagation matters; annotation-only edits need annotation readback.
- Class work satisfies the relevant checks in the skill's class-recovery reference.
- An audit entry appended to `audit/<target>-recovery.md` — using the skill's
  checkpoint-note skeleton — records the changes, the evidence, failed commands,
  remaining uncertainty, and next steps concrete enough for another agent to continue
  without repeating discovery.
