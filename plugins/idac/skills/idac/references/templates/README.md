# Template Files

These templates are generic starting points for common `idac` mutation passes.

- `prototype-preview.idac` and `prototype-pass.idac`
  - Use for a small cluster of related prototype edits after support types already exist.
  - Lint and run the preview file with `--fail-fast`, inspect every before/after result in its journal, then lint and run the commit file with `--fail-fast`.
- `rename-preview.idac` and `rename-pass.idac`
  - Use with `locals-plan.json` for coordinated local renames after reanalysis and a fresh locals dump.
  - Replace every sample selector in the plan, lint and run the preview with `--fail-fast`, inspect the full before/after local lists, then lint and run the commit with `--fail-fast` so the pass stops on the first miss.
- `locals-plan.json`
  - Starting point shared by the `function locals apply` preview and commit files.
  - Copy exact `index` or `local_id` selectors from the fresh locals JSON; do not reuse the sample indices blindly.
- `checkpoint-note.md`
  - Use for per-target `audit/<target>-recovery.md` entries that separate confirmed changes, failures, open questions, and next steps.
- `locals-jq-snippets.sh`
  - Use for inspecting the wrapped `function locals list --json --out ...` artifact shape without rediscovering the `jq` filters.

These are examples, not canonical declarations. In the `.idac` and JSON files, replace the placeholder types, addresses, selectors, and names with evidence from the current target. `checkpoint-note.md` is a fill-in skeleton: replace every `{{...}}` slot and delete sections with nothing to report.
