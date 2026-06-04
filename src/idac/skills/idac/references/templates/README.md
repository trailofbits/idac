# Template Files

These templates are generic starting points for common `idac` mutation passes.

- `prototype-pass.idac`
  - Use for a small cluster of related `function prototype check` / `function prototype set` edits after support types already exist.
  - Run `idac batch prototype-pass.idac --lint -o /tmp/prototype-pass.lint.json` before the real batch.
- `rename-pass.idac`
  - Use for selective local renames after reanalysis and a fresh locals dump.
  - For many edits in one function, prefer a JSON plan consumed by `function locals apply`.
- `checkpoint-note.md`
  - Use for per-target `audit/<target>-recovery.md` entries that separate confirmed changes, failures, open questions, and next steps.
- `locals-jq-snippets.sh`
  - Use for inspecting the wrapped `function locals list --json --out ...` artifact shape without rediscovering the `jq` filters.

These are examples, not canonical declarations. Replace placeholder types, addresses, and names with evidence from the current target.
