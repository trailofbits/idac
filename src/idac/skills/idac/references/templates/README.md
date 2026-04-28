# Template Files

These templates are generic starting points for common `idac` mutation passes.

- `prototype-pass.idac`
  - Use for a small cluster of related `function prototype set` edits after support types already exist.
- `rename-pass.idac`
  - Use for selective local renames after reanalysis and a fresh locals dump.
- `checkpoint-note.md`
  - Use for short pass notes that separate confirmed changes, failures, remaining unknowns, and next steps.
- `locals-jq-snippets.sh`
  - Use for inspecting the wrapped `function locals list --json --out ...` artifact shape without rediscovering the `jq` filters.

These are examples, not canonical declarations. Replace placeholder types, addresses, and names with evidence from the current target.
