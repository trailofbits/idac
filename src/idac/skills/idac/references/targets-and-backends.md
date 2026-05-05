# Targets and Backends

This file documents the current public `idac` surface.

`idac` has two execution contexts:

- `gui`: use a live IDA desktop session through the `idac_bridge` plugin
- `idalib`: use a headless per-database idalib process against an existing `.i64` / `.idb`, or a binary that IDA can open

Do not start every task with diagnostics or cleanup. Use the diagnostic commands in this file when context selection is unclear, target discovery fails, or bridge/runtime trouble is likely.

## Live GUI context

Use the default context or `-c <selector>` when:

- the database is already open in IDA
- you want to review changes in the UI immediately
- you want live mutation or preview behavior against the desktop session

`-c/--context` and `--timeout` can appear either before the subcommand or on the command itself. If you pass both a root-level value and a command-local value, the command-local value wins. Omit `--timeout` to wait indefinitely.

Discover targets first:

```bash
idac doctor
idac targets list
idac decompile "sub_08041337"
idac decompile "sub_08041337" -c "pid:1234"
idac targets cleanup
```

If multiple GUI instances are open, pass `-c pid:<pid>`.
`targets list` reports both live GUI bridge targets and already-open headless `idalib` targets. In JSON output, check `backend`: GUI rows use `backend: "gui"` and headless rows use `backend: "idalib"`. If a binary was opened with `database open`, keep using `-c "db:/path/to/binary"` even when no GUI target is present.
If the runtime dir contains stale GUI bridge or `idalib` daemon files, run `idac targets cleanup` and then rerun `targets list`. Use `--out <path>` when you want to keep the full cleanup result.
If the bridge plugin is missing from the current IDA session, run `idac misc plugin install` and reload the plugin in IDA before retrying discovery.

## Database context

Use `idac database open` when you have a binary or database file and want headless automation without depending on the UI.

For a binary:

```bash
idac database open "/path/to/binary" --json
idac targets list --json
idac database show -c "db:/path/to/binary" --json
idac decompile "main" -c "db:/path/to/binary" --f5
```

For massive binaries or first-time autoanalysis, prefer the indefinite default unless the user asked for a deadline. Do not wrap this import in a shell-level timeout or a tool-call timeout; let the command keep running and poll the session if your tool supports incremental output.
If the raw import does not name `main`, use `start_ea` / `entry_ea` from `database show --json` or an address from `function list --json`.

For an existing `.i64` / `.idb`:

```bash
idac database open "sample.i64"
idac doctor
idac database show -c "db:sample.i64"
idac decompile "sub_08041337" -c "db:sample.i64"
idac database save -c "db:sample.i64"
```


## Selection rules

- If exactly one GUI instance is open, most commands can omit `-c`.
- Explicit `db:` locators passed via `-c` resolve to `idalib`; the path can be a binary or database file that IDA can open.
- `targets list -c "db:/path"` filters to matching headless targets without starting a new daemon.
- GUI selectors passed via `-c` resolve to the live bridge.
- If multiple GUI instances are open, `-c` is required.
- `doctor` is the first command to run when backend state is unclear.
