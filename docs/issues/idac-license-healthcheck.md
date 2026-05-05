# idalib Startup Failures Hide IDA Licensing Problems

## Problem

`idac doctor` reported that `idalib` was importable, but `idac database open <binary>` failed later with only:

```text
idalib daemon failed to start for `<path>`
```

In the observed environment, direct IDA startup logged:

```text
Cannot continue without a valid license
```

The doctor check was incomplete: importing `idapro` does not prove IDA can open a database under the active license and Python configuration. The database-open error path also lost useful context when the `idalib` child exited before writing its readiness payload.

## Expected Behavior

- `idac doctor` should include an `idalib.license` check that validates IDA licensing without opening a user target or bundled smoke database.
- `idac database open` should preserve any child stderr/ready-payload detail and otherwise emit a diagnostic hint that points to IDA startup/license/Python initialization and `idac doctor`.
- If IDA exposes a direct license/status API in the future, prefer that over command-line probing.

## Root Cause

The previous health check stopped at `idapro` import. IDA license validation can happen later, during database open, and can terminate the child process before `idac` receives a structured error.

## Rejected Approach

Do not add a default doctor smoke test that opens a bundled `.i64`. It is heavier than users expect from `doctor`, creates surprising IDA runtime behavior, and still does not guarantee the same loader/database path that the real command will exercise. Use a license-specific check instead.
