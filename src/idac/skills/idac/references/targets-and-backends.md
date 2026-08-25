# Nexus Targets and Contexts

Read this when choosing a live GUI or headless context, opening a binary, or resolving
Nexus discovery state.

Every `idac` operation uses the public ida-nexus API. The supported stack is Python
3.11+, IDA 9.4+, `ida-nexus==0.7.0` with protocol 6, and `ida-domain==0.5.1`.
There is no alternate execution path when discovery, startup, analysis, or execution
fails.

## Select by path

Use `-c/--context PATH` with an `.i64` database or a binary that IDA can open:

```bash
idac database show -c sample.i64 --json
idac decompile "sub_08041337" -c sample.i64 --f5
idac database show -c /path/to/firmware.bin --json
idac decompile "main" -c /path/to/firmware.bin --f5
```

Nexus resolves the path to a matching live GUI database when available, otherwise to a
matching managed worker, and otherwise starts a managed headless worker. Binary input
uses the corresponding `.i64` database identity. Only `.i64` database files are
accepted.

Headless starts enable auto-analysis and wait for completion before the requested
operation runs. This can take a long time for a first import, so choose an explicit,
deliberate `--timeout` when the Nexus defaults may be too short. Live GUI attachment
uses the current analysis state and does not force analysis.

For source-level entry behavior, prefer `main_ea` from `database show --json`. If IDA
cannot determine `main`, use `start_ea`, `entry_ea`, or an address from
`function list --json`. If a raw input requires an interactive loader or architecture
choice, import it in IDA first, make the choice there, and save an `.i64`.

## Select a running instance

List discovery records, then pass the exact `record_id`:

```bash
idac targets list --json
idac decompile "sub_08041337" --instance "<record-id>"
```

`--instance` selects one READY record exactly; it does not perform fuzzy matching.
`targets list` reports `record_id`, `state`, `detail`, `backend`, `pid`, `idb_path`,
`exe_path`, `managed`, and `started_at`. The backend field is descriptive; users do not
choose it independently of the record.

If an exact record is missing or not READY, the command fails and reports discovery
state. It never attaches to a different record.

## Omitted context

With neither `-c` nor `--instance`, `idac` attaches only when discovery returns exactly
one READY Nexus instance:

```bash
idac decompile "sub_08041337"
```

Zero READY instances is an error. Multiple READY instances is also an error; select one
with `--instance` or select a database/input with `-c`.

`-c` and `--instance` are mutually exclusive. Either can appear before the command or
on a context-aware subcommand; a command-local option overrides an inherited root
option. `--timeout` controls Nexus startup, analysis, and operation timeouts. Without
it, startup and operation execution use the pinned Nexus defaults, while idac bounds
the headless analysis wait at 120 seconds. No phase requests an infinite wait.

## Saves and worker lifetime

One top-level invocation owns one Nexus lease. `batch`, previews, and
`decompilemany` reuse that context for all child work.

`batch` and `preview` own the target and timeout for that lease. Put `-c`,
`--instance`, and `--timeout` on the wrapper; child commands that specify any of
those options are rejected. The wrapper timeout is inherited for child validation,
including commands that require an explicit timeout.

- A released managed headless worker remains available for five idle minutes.
- A successful headless mutation is checkpointed before the next remote request or
  before the lease is released. If a later batch step fails or is interrupted,
  earlier successful mutations remain on disk.
- A successful preview is undone and does not mark the database dirty. If preview
  execution or rollback raises, idac poisons the shared session and shuts down the
  headless worker with `save=False`; it never saves uncertain preview-only state.
- Live GUI mutations stay in the current IDA session without an automatic save. Run
  `idac database save --instance "<record-id>"` or select its path explicitly when a
  checkpoint is desired.
- A failed GUI preview or interrupted GUI request cannot be discarded by terminating
  the desktop session. idac releases without saving and reports that the in-memory
  state is uncertain; inspect or undo it in IDA before an explicit save.
- A timeout or disconnect is reported without retrying an operation whose outcome may
  be uncertain.
- A failed headless save is never retried, including by the worker's later idle
  shutdown. idac poisons and discards that worker; because the failure may have arrived
  after disk I/O, reread the database from a fresh worker before deciding what persisted.
- Ctrl-C exits 130 without a traceback. When it interrupts an in-flight headless
  request, idac discards and retires that uncertain worker before returning; rerun the
  command deliberately if the interrupted change is still wanted. Cleanup stays on the
  exact worker and may wait through transient lease-release state; it never reruns the
  interrupted operation or selects another target.
- A failed or interrupted mutating operation, including arbitrary `py exec`, may have
  changed IDA before the error arrived. idac does not retry it. Remote failures such as
  a Nexus timeout are checkpointed once for headless sessions; a local Ctrl-C follows
  the discard rule above. Reread the affected state before continuing.

## Setup and diagnosis

Install the exact matching GUI integration and inspect the stack with:

```bash
idac setup gui
idac doctor
idac targets list --json
```

`setup gui` uses pinned `ida-hcli==0.19.2` to install ida-nexus v0.7.0 with
ida-domain 0.5.1. Restart IDA or load the installed Nexus component as required by IDA,
then rerun discovery. `doctor` is read-only and reports local package versions, the
installed GUI component, discovery records, and versions inside READY instances.
