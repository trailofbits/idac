# Class Recovery Pass

Use this for C++ classes, vtables, hierarchies, or related class-family cleanup.

## Setup

- **Context**: <!-- -c db:/path/to/file.i64, -c pid:1234, or blank to use AGENTS.md default -->
- **Target**: <!-- class, vtable, symbol prefix, or class family -->
- **Scope**: <!-- exact classes/functions to include and exclude -->
- **Objective**: <!-- layout, vtable, prototype, caller readability, or locals cleanup goal -->
- **Prior work**: <!-- audit entry, recovered header, artifact path, or "none" -->

If any required placeholder is still blank at runtime, ask instead of guessing.

## References

If the idac guide is not already in context, run `idac docs guide` first. For this pass, also use:

- `idac docs class-recovery`
- `idac docs ida-cpp-type-details`
- `idac docs workflows`
- `idac docs cli`

## Class-Specific Expectations

- Start from confirmed family members, then widen to callers or adjacent helpers only when readback requires it.
- Recover support types before dependent prototypes and before cosmetic local cleanup.
- Use the vtable import -> redecompile with `--f5` -> refine -> re-import loop when virtual dispatch is relevant.
- Apply prototypes to runtime virtual targets, not just local vtable slot types.
- Validate class headers with `type check` before import, and use `type deps` when a dependency-expanded type declaration should be captured.
- Validate high-risk virtual target signatures with `function prototype check` before `function prototype set`.
- Before a mutation batch, run `batch --lint --out .idac/tmp/<target>.lint.json`.
- After reanalysis, use fresh locals JSON plus stable selectors or `function locals apply` for local cleanup.
- Keep uncertain field, member, parameter, and local names explicitly provisional.

## Artifacts

- Recovered or refined declarations: `headers/recovered/<target>.h`
- Preview and mutation logs: `.idac/tmp/` unless they must be durable
- Pass notes: `audit/<target>-recovery.md`

## Audit Entry

Append to `audit/<target>-recovery.md` using `references/templates/checkpoint-note.md` inside this workspace or `idac docs templates`.

## Done When

- The relevant class layout, vtable evidence, and important call behavior are readable enough for the stated objective.
- Representative constructors, destructors, overrides, helpers, or callers have been reread after changes.
- Any remaining uncertainty is captured in the audit entry instead of hidden in confident names.
