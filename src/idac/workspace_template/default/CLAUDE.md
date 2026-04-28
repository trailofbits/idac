# Workspace

This is an idac reverse-engineering workspace.

## Structure

- `audit/` — audit notes and findings
- `headers/recovered/` — headers reconstructed from reversing
- `headers/vendor/` — reference headers from SDKs or public source
- `reference/` — local copies of the bundled IDA and idac reference docs
- `scripts/` — reusable idac/IDA Python scripts
- `prompts/` — reusable agent prompts
- `.idac/tmp/` — scratch space for transient output (gitignored)

## Default target

<!-- Set your default target here so the agent knows which database to use -->
<!-- Example: -c db:/path/to/firmware.i64 -->

## Conventions

- Use `idac` for all IDA interactions — do not script IDA directly
- Read `reference/cli.md` before copying command examples from the workspace prompts
- Refer to `reference/class-recovery.md` when doing class-recovery work
- Refer to `reference/ida-cpp-type-details.md` when making types for C++ classes or vtables
- Write findings to `audit/`
- Store reusable type definitions in `headers/`
- Store reusable scripts in `scripts/`
- Use `.idac/tmp/` for large transient `--out` files
