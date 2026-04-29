from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class DatabaseInfoRequest:
    pass


@dataclass(frozen=True)
class DatabaseSaveRequest:
    path: str | None = None


def _parse_info(_params: Mapping[str, Any]) -> DatabaseInfoRequest:
    return DatabaseInfoRequest()


def _parse_save(params: Mapping[str, Any]) -> DatabaseSaveRequest:
    path = str(params.get("path") or "").strip()
    return DatabaseSaveRequest(path=path or None)


def _database_info(runtime: IdaRuntime, request: DatabaseInfoRequest) -> dict[str, object]:
    del request
    ida_entry = runtime.mod("ida_entry")
    ida_ida = runtime.mod("ida_ida")
    ida_loader = runtime.mod("ida_loader")
    idaapi = runtime.mod("idaapi")
    entry_ord = ida_entry.get_entry_ordinal(0)
    entry_ea = ida_entry.get_entry(entry_ord) if entry_ord != idaapi.BADADDR else idaapi.BADADDR
    start_ea = ida_ida.inf_get_start_ea()
    return {
        "path": idaapi.get_input_file_path() or "",
        "database_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
        "module": idaapi.get_root_filename() or "",
        "processor": ida_ida.inf_get_procname(),
        "bits": runtime.database_bits(),
        "base": hex(idaapi.get_imagebase()),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
        "start_ea": None if start_ea == idaapi.BADADDR else hex(start_ea),
        "entry_ea": None if entry_ea == idaapi.BADADDR else hex(entry_ea),
    }


def _database_save(runtime: IdaRuntime, request: DatabaseSaveRequest) -> dict[str, object]:
    ida_loader = runtime.mod("ida_loader")
    save_path = request.path or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    if not save_path:
        raise IdaOperationError("could not resolve database path")
    if not bool(ida_loader.save_database(save_path, 0)):
        raise IdaOperationError(f"failed to save database: {save_path}")
    return {"saved": True, "path": save_path}


def _run_database_info(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _database_info(runtime, _parse_info(params))


def _run_database_save(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _database_save(runtime, _parse_save(params))


DATABASE_OPS: dict[str, Op] = {
    "database_info": Op(run=_run_database_info),
    "db_save": Op(run=_run_database_save, mutating=True),
}


__all__ = [
    "DATABASE_OPS",
    "DatabaseInfoRequest",
    "DatabaseSaveRequest",
]
