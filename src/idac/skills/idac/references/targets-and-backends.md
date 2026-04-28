# Targets and Backends

This file documents the current public `idac` surface.

`idac` has two execution contexts:

- `gui`: use a live IDA desktop session through the `idac_bridge` plugin
- `idalib`: use a headless per-database idalib process against an existing `.i64` / `.idb`

Do not start every task with diagnostics or cleanup. Use the diagnostic commands in this file when context selection is unclear, target discovery fails, or bridge/runtime trouble is likely.

## Live GUI context

Use the default context or `-c <selector>` when:

- the database is already open in IDA
- you want to review changes in the UI immediately
- you want live mutation or preview behavior against the desktop session

`-c/--context` and `--timeout` can appear either before the subcommand or on the command itself. If you pass both a root-level value and a command-local value, the command-local value wins.

Discover targets first:

```bash
idac doctor
idac targets list
idac decompile "sub_08041337"
idac decompile "sub_08041337" -c "pid:1234"
idac targets cleanup
```

If multiple GUI instances are open, pass `-c pid:<pid>`.
If the runtime dir contains stale GUI bridge or `idalib` daemon files, run `idac targets cleanup` and then rerun `targets list`. Use `--out <path>` when you want to keep the full cleanup result.
If the bridge plugin is missing from the current IDA session, run `idac misc plugin install` and reload the plugin in IDA before retrying discovery.

## Database context

Use `-c "db:/path/to/file.i64"` or `-c "db:/path/to/file.idb"` when:

- you already have an `.i64` / `.idb`
- you want headless automation
- you want deterministic test coverage without depending on the UI

Example:

```bash
idac database open "sample.i64"
idac doctor
idac database show -c "db:sample.i64"
idac decompile "sub_08041337" -c "db:sample.i64"
idac database save -c "db:sample.i64"
```


## Selection rules

- If exactly one GUI instance is open, most commands can omit `-c`.
- Explicit `db:` locators passed via `-c` resolve to `idalib`.
- GUI selectors passed via `-c` resolve to the live bridge.
- If multiple GUI instances are open, `-c` is required.
- `doctor` is the first command to run when backend state is unclear.
