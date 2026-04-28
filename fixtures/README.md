## Fixtures

This directory contains the committed binaries, IDA databases, logs, and source used by `idac` tests.

Current committed fixture artifacts are Mach-O ARM64 binaries and `.i64` databases generated on macOS/Apple Silicon.

### `tiny`

Small C fixture used for lightweight CLI, transport, and backend checks.

- source: `src/tiny.c`
- build helper: `scripts/build_tiny.sh`
- database helper: `scripts/make_idbs.sh`
- generated outputs:
  - `build/tiny`
  - `build/tiny.stripped`
  - `idb/tiny.i64`
  - `idb/tiny_stripped.i64`

### `handler_hierarchy`

Primary class-recovery fixture used for type, vtable, and hierarchy tests.

- source: `src/handler_hierarchy.cpp`
- importable type header: `src/handler_hierarchy.hpp`
- build helper: `scripts/build_handler_hierarchy.sh`
- database helper: `scripts/make_handler_hierarchy_idbs.sh`
- generated outputs:
  - `build/handler_hierarchy`
  - `build/handler_hierarchy.stripped`
  - `idb/handler_hierarchy.i64`
  - `idb/handler_hierarchy_stripped.i64`

### Regeneration

Run from the repository root:

```bash
bash fixtures/scripts/build_tiny.sh
bash fixtures/scripts/make_idbs.sh
bash fixtures/scripts/build_handler_hierarchy.sh
bash fixtures/scripts/make_handler_hierarchy_idbs.sh
```

If `strip` is unavailable, the build scripts still generate the unstripped binaries and log a note.
