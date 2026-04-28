from __future__ import annotations

import os
import signal
import sys
import traceback
from pathlib import Path

# pro tip from ida-pro-mcp
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def _bootstrap_paths() -> None:
    here = Path(__file__).resolve()
    plugin_dir = here.parent
    if str(plugin_dir) not in sys.path:
        sys.path.insert(0, str(plugin_dir))

    candidates: list[Path] = []
    raw_repo = os.environ.get("IDAC_REPO")
    if raw_repo:
        candidates.append(Path(raw_repo).expanduser().resolve())
    candidates.append(plugin_dir.parent)

    for repo_root in candidates:
        src_dir = repo_root / "src"
        if (src_dir / "idac").exists():
            if str(src_dir) not in sys.path:
                sys.path.insert(0, str(src_dir))
            break


_bootstrap_paths()


import ida_kernwin  # type: ignore
import idaapi  # type: ignore
from idac_bridge.bridge import BridgeService
from idac_bridge.protocol import registry_path, socket_path

from idac.version import VERSION

REQUEST_LOG_FLAG = 0x1
RESPONSE_LOG_FLAG = 0x2


class _BridgeLoggingForm(getattr(ida_kernwin, "Form", object)):
    def __init__(self) -> None:
        super().__init__(
            f"""BUTTON YES* OK
BUTTON CANCEL Cancel
idac bridge

Version: {VERSION}

<Log incoming commands:{{requestLog}}>
<Log outgoing responses:{{responseLog}}>{{loggingFlags}}>
""",
            {
                "loggingFlags": ida_kernwin.Form.ChkGroupControl(("requestLog", "responseLog")),
            },
        )


class IdacBridgePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Expose the active IDA session to the idac CLI"
    help = "Starts a local Unix-socket bridge for idac"
    wanted_name = "idac bridge"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self._service: BridgeService | None = None

    def _log(self, message: str, *, exc: BaseException | None = None) -> None:
        lines = [f"[idac] {message}\n"]
        if exc is not None:
            lines.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        text = "".join(lines)
        idaapi.msg(text)

    def init(self):
        try:
            self._service = BridgeService()
            self._service.start()
            self._emit_status()
            return idaapi.PLUGIN_KEEP
        except Exception as exc:
            self._service = None
            self._log("GUI bridge failed to start", exc=exc)
            return idaapi.PLUGIN_SKIP

    def _emit_status(self) -> None:
        pid = os.getpid()
        state = "running" if self._service is not None else "not running"
        message = (
            f"[idac] idac bridge v{VERSION} loaded\n"
            f"[idac] GUI bridge {state} (v{VERSION}): "
            f"pid={pid}, socket={socket_path(pid)}, registry={registry_path(pid)}\n"
        )
        idaapi.msg(message)

    def run(self, _arg: int) -> None:
        self._show_logging_dialog()
        return None

    def _show_logging_dialog(self) -> None:
        service = self._service
        if service is None:
            self._emit_status()
            return

        form = _BridgeLoggingForm()
        form, _ = form.Compile()
        form.loggingFlags.value = self._current_logging_flags()
        try:
            form.Execute()
            self._apply_logging_flags(form.loggingFlags.value)
        finally:
            form.Free()
        self._emit_status()

    def _current_logging_flags(self) -> int:
        service = self._service
        if service is None:
            return 0
        flags = 0
        if service.request_logging_enabled:
            flags |= REQUEST_LOG_FLAG
        if service.response_logging_enabled:
            flags |= RESPONSE_LOG_FLAG
        return flags

    def _apply_logging_flags(self, flags: int) -> None:
        service = self._service
        if service is None:
            return
        service.set_request_logging_enabled(bool(flags & REQUEST_LOG_FLAG))
        service.set_response_logging_enabled(bool(flags & RESPONSE_LOG_FLAG))

    def term(self) -> None:
        if self._service is not None:
            try:
                self._service.stop()
            except Exception as exc:
                self._log("GUI bridge failed during shutdown", exc=exc)
            finally:
                self._service = None


def PLUGIN_ENTRY():
    return IdacBridgePlugin()
