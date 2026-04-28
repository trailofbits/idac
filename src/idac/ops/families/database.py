from __future__ import annotations

from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..runtime import IdaOperationError


@dataclass(frozen=True)
class DatabaseInfoRequest:
    pass


@dataclass(frozen=True)
class DatabaseSaveRequest:
    path: str | None = None


def _parse_info(_params: dict[str, object]) -> DatabaseInfoRequest:
    return DatabaseInfoRequest()


def _parse_save(params: dict[str, object]) -> DatabaseSaveRequest:
    path = str(params.get("path") or "").strip()
    return DatabaseSaveRequest(path=path or None)


def _database_info(context: OperationContext, request: DatabaseInfoRequest) -> dict[str, object]:
    del request
    runtime = context.runtime
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


def _database_save(context: OperationContext, request: DatabaseSaveRequest) -> dict[str, object]:
    runtime = context.runtime
    ida_loader = runtime.mod("ida_loader")
    save_path = request.path or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    if not save_path:
        raise IdaOperationError("could not resolve database path")
    if not bool(ida_loader.save_database(save_path, 0)):
        raise IdaOperationError(f"failed to save database: {save_path}")
    return {"saved": True, "path": save_path}


def database_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="database_info",
            parse=_parse_info,
            run=_database_info,
        ),
        OperationSpec(
            name="db_save",
            parse=_parse_save,
            run=_database_save,
            mutating=True,
        ),
    )


__all__ = [
    "DatabaseInfoRequest",
    "DatabaseSaveRequest",
    "database_operations",
]
