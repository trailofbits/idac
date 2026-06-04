# Reverse Engineer

Use this for a broader type/prototype recovery pass or multi-target reversing effort.

## Setup

- **Context**: <!-- -c db:/path/to/file.i64, -c pid:1234, or blank to use AGENTS.md default -->
- **Target**: <!-- symbol, class, family, module, or behavior under analysis -->
- **Scope**: <!-- single function, class, class family, module, or bounded behavior -->
- **Objective**: <!-- what should become readable, typed, or evidenced -->
- **Prior work**: <!-- audit entry, recovered header, artifact path, or "none" -->

If any required placeholder is still blank at runtime, ask instead of guessing.

## References

If the idac guide is not already in context, run `idac docs guide` first. Use focused topics as needed:

- `idac docs targets` for context/backend selection and opening binaries
- `idac docs cli` for command grammar and output behavior
- `idac docs workflows` for preview, batch, mutation, reanalysis, and locals selectors
- `idac docs class-recovery` for C++ family recovery
- `idac docs ida-cpp-type-details` for IDA C++ declaration and vtable syntax
- `idac docs troubleshooting` for bridge, backend, or stale-result issues

## Triage For Broad Targets

Skip this section for a single well-defined target. For a class family, module, or multiple targets:

1. Capture the function/type surface with filtered `function list`, `type list`, and class-candidate reads.
2. Prioritize base types, common support structs, shared helpers, and prototypes that dominate many callers.
3. Establish dependency order: support types before prototypes, base layouts before derived layouts, prototypes before local cleanup.
4. Check `audit/` and `headers/recovered/` so prior work is extended rather than rediscovered.
5. Record the priority order in `audit/<target>-triage.md` if the pass spans multiple targets.

## Recovery Focus

- Prefer one incremental pass that improves the database and leaves a clear handoff.
- For virtual classes, use the vtable import -> redecompile with `--f5` -> refine -> re-import loop until readback stops revealing structural facts.
- Include directly blocking support types or enums, but do not expand into adjacent families without evidence that the scoped objective requires it.
- Keep per-target headers separate unless types are tightly coupled.

## Artifacts

- Recovered declarations: `headers/recovered/<target>.h`
- Durable notes: `audit/<target>-recovery.md`
- Multi-target triage: `audit/<target>-triage.md`
- Transient previews, locals JSON, and decompile dumps: `.idac/tmp/`

## Audit Entry

Append to `audit/<target>-recovery.md` using `references/templates/checkpoint-note.md` inside this workspace or `idac docs templates`.

## Continuing Prior Work

Read the latest audit entry and relevant header first. Start from the latest open questions or TODOs, spot-check that they still match the database, then continue with a narrow pass. If the audit is stale, note the mismatch and start fresh discovery for the affected area.

## Done When

- The stated objective is improved and verified with representative readback.
- Database/header changes are recorded with evidence and remaining uncertainty.
- Failed commands, parser limits, or tooling rough edges are called out.
- Next steps are concrete enough for another agent to continue without repeating discovery.
