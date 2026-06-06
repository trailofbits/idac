# Workspace

This is an idac reverse-engineering workspace.
If the idac guide is not already in context, run `idac docs guide`. Detailed references are available under `references/` and via `idac docs TOPIC`.

## Structure

- `audit/` — audit notes and findings
- `headers/recovered/` — headers reconstructed from reversing
- `headers/vendor/` — reference headers from SDKs or public source
- `references/` — local copies of the bundled IDA and idac reference docs
- `scripts/` — reusable idac/IDA Python scripts
- `prompts/` — reusable agent prompts
- `.idac/tmp/` — scratch space for transient output (gitignored)

## Default target

<!-- Set your default target here so the agent knows which database to use -->
<!-- Example: -c db:/path/to/firmware.i64 -->
<!-- Per-task prompt Context values override this default. If both are blank, ask before guessing. -->

## Prompt routing

- `prompts/general-analysis.md` - light scoped analysis or one incremental improvement pass
- `prompts/class-recovery-pass.md` - C++ class, vtable, hierarchy, or family recovery
- `prompts/reverse-engineer.md` - broader type/prototype recovery or multi-phase reversing work

## Conventions

- References are canonical; when command syntax is unclear or errors, check `references/cli.md` or `idac docs cli`.
- Write findings to `audit/`
- Store reusable type definitions in `headers/`
- Store reusable scripts in `scripts/`
- Use `.idac/tmp/` for large transient `--out` files
- Before executing mutation batches, run `idac batch <file> --lint --out .idac/tmp/<name>.lint.json`.
- Validate parser-risky declarations with `type check` or `function prototype check` before mutating.
- After type/prototype mutations and reanalysis, use fresh `function locals list --json` data; prefer `--local-id`, `--index`, or `function locals apply`.
- Keep pass updates and audit notes concise and factual; skip tutorial explanations unless asked.
