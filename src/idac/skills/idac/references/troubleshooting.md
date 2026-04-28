# Troubleshooting

This file documents the current public `idac` surface.

## No GUI targets found

Run:

```bash
idac misc plugin install
idac doctor
idac targets list
idac targets cleanup
```

If no targets appear, either the IDA plugin bridge is not loaded in the current GUI session or stale bridge runtime files are masking the live session. Run `idac targets cleanup --out <path>` when you need the full cleanup result, then rerun `targets list`.

## Agent sandbox cannot reach the bridge socket

Both backends use Unix sockets (default runtime dir: `/tmp/idac`, controlled by `IDAC_RUNTIME_DIR`). If your environment blocks Unix socket connections, *every* live GUI command will fail with errors like "Failed to contact IDA GUI bridge".

The bridge socket does not distinguish read-only vs mutating operations. If read-only commands succeed but a mutation fails, focus on the reported IDA/database failure mode (for example: IDA undo disabled for `preview`, a read-only database, missing types, or a rejected declaration) rather than sandbox socket permissions.

## Multiple GUI targets are open

Use an explicit selector from `targets list`:

```bash
idac targets list
idac decompile "sub_08041337" -c "pid:<pid>"
```

## `idalib` requires a database

The `idalib` backend expects an existing `.i64` / `.idb`:

```bash
idac database show -c "db:sample.i64"
```

## `idalib` changes did not reach disk

That is expected until you save the open database:

```bash
idac database save -c "db:sample.i64"
idac database close -c "db:sample.i64"
```

## Preview did not persist

That is expected. `preview` applies the mutation, captures the result, and undoes it before returning.

```bash
idac preview -o "/tmp/preview.json" comment set "sub_08041337" "entry point"
```

Preview performs the real mutation before undoing it, so the readback reflects the temporary changed state.

For `function locals update`, `function locals rename`, and `function locals retype`, preview always returns the full before/after local list.

Preview payloads are structured JSON or JSONL objects with these top-level keys:

- `command`
- `status`
- `before`
- `after`
- `result`
- `readback`
- `undo`
- `artifacts`
- `stderr`

For mutating commands, `before` and `after` capture the temporary state around the undo cycle, and `result` contains the command-specific return payload.

For `type declare` previews, `replaced_types` is the list of local types whose declarations changed in the preview. It is informational, not a failure signal. If a familiar framework typedef such as `CFDateRef` appears there, verify the local type directly with `type show` before treating it as a regression.

## `type class show` says the type is not class-materialized

That means the local type exists, but not yet as a C++ class that `idac` can flatten or inspect as a vtable-backed object.

Run:

```bash
idac type show "ExampleClass"
idac type class candidates "ExampleClass" --json --out "/tmp/class_candidates.json"
idac preview -o "/tmp/type_preview.json" type declare --replace --decl-file "recovered_classes.h"
```

If the candidates show vtable, RTTI, or family function symbols, switch to recovered-header import instead of probing more `type class show` or `type class vtable` commands on the opaque type.

## Decompiler, local, or type results look stale

Run:

```bash
idac misc reanalyze "sub_08041337"
idac decompile "sub_08041337"
idac decompile "sub_08041337" --f5
```

`--f5` is an alias for `--no-cache` and forces a fresh Hex-Rays pass instead of reusing cached pseudocode.
If the issue is backend-related, rerun `doctor` first.

## Large readback is hard to inspect inline

If a function, local-variable list, or decompile result is too large for the terminal, write it to a file instead of relying on inline output:

```bash
idac decompile "sub_08041337" --f5 --out "/tmp/sub_08041337.json"
idac function locals list "sub_08041337" --json --out "/tmp/sub_08041337.locals.json"
idac decompilemany "Example_" --out-dir "/tmp/example_family"
```

When the output is mostly for later inspection, prefer a file artifact from the start. That keeps the readback stable across reanalysis and avoids truncation.
