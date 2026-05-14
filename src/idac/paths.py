from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .metadata import (
    BRIDGE_PLUGIN_NAME,
    BRIDGE_REGISTRY_PREFIX,
    BRIDGE_RUNTIME_DIRNAME,
    BRIDGE_SOCKET_PREFIX,
    IDALIB_REGISTRY_PREFIX,
    IDALIB_SOCKET_PREFIX,
    SKILL_NAME,
)


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else default


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _default_ida_user_dir() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def package_source_dir() -> Path:
    return Path(__file__).resolve().parent


def codex_home() -> Path:
    return _env_path("CODEX_HOME", Path.home() / ".codex")


def claude_home() -> Path:
    return _env_path("CLAUDE_HOME", Path.home() / ".claude")


def runtime_uid_token() -> str:
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return "nouid"
    return str(int(getuid()))


def ida_user_dir() -> Path:
    return _env_path("IDAUSR", _default_ida_user_dir())


def ida_config_path() -> Path:
    return ida_user_dir() / "ida-config.json"


def ida_configured_install_dir() -> Path | None:
    try:
        payload = json.loads(ida_config_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    paths = payload.get("Paths")
    if not isinstance(paths, dict):
        return None
    raw_install_dir = paths.get("ida-install-dir")
    if not isinstance(raw_install_dir, str) or not raw_install_dir.strip():
        return None
    return Path(raw_install_dir).expanduser()


def hcli_config_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "hcli"
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base).expanduser() / "hex-rays" / "hcli"
        return Path.home() / "AppData" / "Local" / "hex-rays" / "hcli"
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base).expanduser() / "hcli"
    return Path.home() / ".config" / "hcli"


def hcli_configured_install_dir() -> Path | None:
    try:
        config_path = hcli_config_dir() / "config.json"
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    default_name = payload.get("ida.default")
    if not isinstance(default_name, str) or not default_name.strip():
        return None
    instances = payload.get("ida.instances")
    if not isinstance(instances, dict):
        return None
    raw_install_dir = instances.get(default_name)
    if not isinstance(raw_install_dir, str) or not raw_install_dir.strip():
        return None
    return Path(raw_install_dir).expanduser()


def runtime_dir() -> Path:
    return _env_path("IDAC_RUNTIME_DIR", Path("/tmp") / BRIDGE_RUNTIME_DIRNAME)


def user_runtime_dir() -> Path:
    return runtime_dir()


def ensure_user_runtime_dir() -> Path:
    return _ensure_dir(user_runtime_dir())


def bridge_registry_filename(pid: int) -> str:
    return f"{BRIDGE_REGISTRY_PREFIX}-{runtime_uid_token()}-{pid}.json"


def bridge_socket_filename(pid: int) -> str:
    return f"{BRIDGE_SOCKET_PREFIX}-{runtime_uid_token()}-{pid}.sock"


def bridge_registry_path(pid: int | None = None) -> Path:
    resolved_pid = os.getpid() if pid is None else pid
    return user_runtime_dir() / bridge_registry_filename(resolved_pid)


def bridge_socket_path(pid: int | None = None) -> Path:
    resolved_pid = os.getpid() if pid is None else pid
    return user_runtime_dir() / bridge_socket_filename(resolved_pid)


def _runtime_path(filename: str) -> Path:
    return user_runtime_dir() / filename


def bridge_registry_paths() -> list[Path]:
    runtime = user_runtime_dir()
    if not runtime.exists():
        return []
    return sorted(runtime.glob(f"{BRIDGE_REGISTRY_PREFIX}-*.json"))


def idalib_registry_filename(pid: int) -> str:
    return f"{IDALIB_REGISTRY_PREFIX}-{runtime_uid_token()}-{pid}.json"


def idalib_socket_filename(pid: int) -> str:
    return f"{IDALIB_SOCKET_PREFIX}-{runtime_uid_token()}-{pid}.sock"


def idalib_registry_path(pid: int | None = None) -> Path:
    resolved_pid = os.getpid() if pid is None else pid
    return _runtime_path(idalib_registry_filename(resolved_pid))


def idalib_socket_path(pid: int | None = None) -> Path:
    resolved_pid = os.getpid() if pid is None else pid
    return _runtime_path(idalib_socket_filename(resolved_pid))


def idalib_registry_paths() -> list[Path]:
    runtime = user_runtime_dir()
    if not runtime.exists():
        return []
    return sorted(runtime.glob(f"{IDALIB_REGISTRY_PREFIX}-*.json"))


def plugin_source_dir() -> Path:
    return package_source_dir() / "ida_plugin" / BRIDGE_PLUGIN_NAME


def plugin_install_dir() -> Path:
    return ida_user_dir() / "plugins" / BRIDGE_PLUGIN_NAME


def plugin_bootstrap_source_path() -> Path:
    return package_source_dir() / "ida_plugin" / "idac_bridge_plugin.py"


def plugin_bootstrap_install_path() -> Path:
    return ida_user_dir() / "plugins" / "idac_bridge_plugin.py"


def plugin_runtime_package_source_dir() -> Path:
    return package_source_dir()


def plugin_runtime_package_install_dir() -> Path:
    return ida_user_dir() / "plugins" / package_source_dir().name


def codex_skills_dir() -> Path:
    return codex_home() / "skills"


def ensure_codex_skills_dir() -> Path:
    return _ensure_dir(codex_skills_dir())


def claude_skills_dir() -> Path:
    return claude_home() / "skills"


def ensure_claude_skills_dir() -> Path:
    return _ensure_dir(claude_skills_dir())


def skill_source_dir() -> Path:
    return package_source_dir() / "skills" / SKILL_NAME


def skill_reference_source_dir() -> Path:
    return skill_source_dir() / "references"


def workspace_template_source_dir() -> Path:
    return package_source_dir() / "workspace_template" / "default"


def skill_install_dir(*, host: str = "codex") -> Path:
    if host == "codex":
        return codex_skills_dir() / SKILL_NAME
    if host == "claude":
        return claude_skills_dir() / SKILL_NAME
    raise ValueError(f"unsupported skill host: {host}")


def skill_install_dirs(*, host: str = "both") -> list[Path]:
    if host == "both":
        deduped: list[Path] = []
        for candidate in (
            skill_install_dir(host="claude"),
            skill_install_dir(host="codex"),
        ):
            if candidate not in deduped:
                deduped.append(candidate)
        return deduped
    return [skill_install_dir(host=host)]
