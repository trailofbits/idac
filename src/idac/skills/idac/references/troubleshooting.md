# Troubleshooting

Read this when Nexus discovery, target selection, runtime compatibility, mutations, or
decompiler readback is unclear.

## No READY Nexus instances found

Diagnose before installing anything:

```bash
idac doctor
idac targets list --json
```

For a live GUI, run `idac setup gui` when `doctor` reports that the matching Nexus
component is missing, then restart IDA or load the component as required by IDA. The
supported versions are ida-nexus 0.7.0, ida-domain 0.5.1, IDA 9.4+, and Python 3.11+.
Any mismatch is an error.

For headless work, pass the `.i64` or binary path directly:

```bash
idac database show -c /path/to/sample.i64 --json
```

Nexus will reuse a matching instance or start a managed worker. If startup fails, fix
the reported IDA, license, path, or version problem; idac does not switch execution
mechanisms.

## A record is BLOCKED or unavailable

`targets list --json` preserves the Nexus `state` and `detail`. A command attaches only
to a READY record. BLOCKED, stale, busy, or disconnected records are not silently
replaced, and an operation is not retried after a connection failure. Resolve the
reported owner/version/liveness problem or select another known target explicitly.

## Multiple READY instances are open

Use the exact record ID from `targets list`:

```bash
idac targets list --json
idac decompile "sub_08041337" --instance "<record-id>"
```

Alternatively, use `-c PATH` to select an `.i64` or binary identity. With no selector,
idac proceeds only when exactly one READY instance exists.

## Headless analysis takes a long time

Headless opens request auto-analysis and wait for it before dispatch. A first binary
import may therefore take much longer than later commands. Supply a deliberate Nexus
timeout when its defaults are too short. Live GUI attachment never forces analysis.

## Changes did not reach disk

Successful headless mutations are checkpointed when the command releases its Nexus
lease; the managed worker then remains warm for five idle minutes. If a save fails, the
command reports the failure.

Live GUI mutations deliberately remain unsaved. Checkpoint them explicitly with
`idac database save`, using `--instance RECORD_ID` or `-c PATH` when selection would
otherwise be ambiguous.

## `function prototype set` reports unknown type(s)

Declare the missing support or placeholder types first, then retry the prototype. See `idac docs workflows` for the safe mutation loop and `idac docs class-recovery` for support-type ordering.

Before retrying, use:

```bash
idac type check --decl-file "support_types.h"
idac function prototype check "sub_08041337" --decl-file "sub_08041337_proto.h"
```

If a local type exists but its dependencies are unclear, use `type deps <name>` to ask IDA to print the type with dependencies when possible.

## Preview did not persist

That is expected. `preview` applies the mutation, captures the result, and restores the prior state before returning.

```bash
idac preview -o "/tmp/preview.json" comment set "sub_08041337" "entry point"
```

Preview performs the real mutation before restoring it, so the readback reflects the temporary changed state.

For `function locals update`, `function locals rename`, and `function locals retype`, preview always returns the full before/after local list.
For `function locals apply`, preview also returns before/after local lists, so use it when a single function has many coordinated local changes.

Preview payloads are structured JSON or JSONL objects; see [cli.md](cli.md#preview) for the top-level key list. For mutating commands, `before` and `after` capture the temporary state around the rollback cycle, and `result` contains the command-specific return payload.

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
idac function locals list "sub_08041337" --json --out "/tmp/sub_08041337.locals.json"
```

`--f5` forces a fresh Hex-Rays pass instead of reusing cached pseudocode.
If the issue appears related to the selected instance or runtime, rerun `doctor` first.

## Large readback is hard to inspect inline

If a function, local-variable list, or decompile result is too large for the terminal, write it to a file instead of relying on inline output:

```bash
idac decompile "sub_08041337" --f5 --out "/tmp/sub_08041337.json"
idac function locals list "sub_08041337" --json --out "/tmp/sub_08041337.locals.json"
idac decompilemany "Example_" --out-dir "/tmp/example_family"
idac disasm --start "0x100000460" --end "0x1000004a0" --out "/tmp/range.asm"
```

When the output is mostly for later inspection, prefer a file artifact from the start. That keeps the readback stable across reanalysis and avoids truncation.
