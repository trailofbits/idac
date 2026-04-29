from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import require_str
from ..preview import PreviewSpec
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class BookmarkGetRequest:
    slot: int | None = None


@dataclass(frozen=True)
class BookmarkSetRequest:
    slot: int
    identifier: str
    comment: str = ""


@dataclass(frozen=True)
class BookmarkAddRequest:
    identifier: str
    comment: str = ""


@dataclass(frozen=True)
class BookmarkDeleteRequest:
    slot: int


def _require_identifier(value: object, *, label: str) -> str:
    return require_str(value, field=label)


def _bookmark_payload(
    *,
    slot: int,
    present: bool,
    address: str | None,
    comment: str | None,
    changed: bool | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "slot": slot,
        "present": present,
        "address": address,
        "comment": comment,
    }
    if changed is not None:
        payload["changed"] = changed
    return payload


def _parse_slot(value: object) -> int:
    text = str("" if value is None else value).strip()
    if not text:
        raise IdaOperationError("bookmark slot is required")
    try:
        slot = int(text, 0)
    except ValueError as exc:
        raise IdaOperationError("bookmark slot must be an integer") from exc
    if slot < 0:
        raise IdaOperationError("bookmark slot must be greater than or equal to 0")
    return slot


def _validate_slot(runtime: IdaRuntime, slot: int) -> int:
    ida_moves = runtime.mod("ida_moves")
    if slot > ida_moves.MAX_MARK_SLOT:
        raise IdaOperationError(f"bookmark slot must be less than or equal to {ida_moves.MAX_MARK_SLOT}")
    return slot


def _bookmark_template(runtime: IdaRuntime):
    ida_kernwin = runtime.mod("ida_kernwin")
    ida_moves = runtime.mod("ida_moves")
    place_id = ida_kernwin.get_place_class_id("idaplace_t")
    if place_id < 0:
        raise IdaOperationError("failed to resolve IDA bookmark place class")
    place = ida_kernwin.get_place_class_template(place_id)
    if place is None:
        raise IdaOperationError("failed to build an idaplace_t template for bookmarks")
    loc = ida_moves.lochist_entry_t()
    loc.set_place(place)
    return loc


def _bookmark_state(runtime: IdaRuntime, slot: int) -> dict[str, object]:
    ida_kernwin = runtime.mod("ida_kernwin")
    ida_moves = runtime.mod("ida_moves")
    loc = _bookmark_template(runtime)
    desc, found_slot = ida_moves.bookmarks_t.get(loc, slot, None)
    if desc is None or found_slot is None:
        return _bookmark_payload(slot=slot, present=False, address=None, comment=None)
    place = loc.place()
    idaplace = ida_kernwin.place_t.as_idaplace_t(place)
    if idaplace is None:
        raise IdaOperationError(f"failed to decode bookmark slot {slot}")
    address = hex(idaplace.ea)
    return _bookmark_payload(
        slot=slot,
        present=True,
        address=address,
        comment=desc,
    )


def _bookmark_slots(runtime: IdaRuntime) -> list[int]:
    ida_moves = runtime.mod("ida_moves")
    return [slot for slot in range(ida_moves.MAX_MARK_SLOT + 1) if _bookmark_state(runtime, slot)["present"]]


def _bookmark_list(runtime: IdaRuntime) -> dict[str, object]:
    bookmarks = [_bookmark_state(runtime, slot) for slot in _bookmark_slots(runtime)]
    return {"bookmarks": bookmarks, "count": len(bookmarks)}


def _first_free_slot(runtime: IdaRuntime) -> int:
    ida_moves = runtime.mod("ida_moves")
    for slot in range(ida_moves.MAX_MARK_SLOT + 1):
        if not _bookmark_state(runtime, slot)["present"]:
            return slot
    raise IdaOperationError(f"no free bookmark slots remain (0..{ida_moves.MAX_MARK_SLOT})")


def _first_free_bookmark_slot(runtime: IdaRuntime) -> int:
    return _first_free_slot(runtime)


def _erase_bookmark(runtime: IdaRuntime, slot: int) -> None:
    ida_moves = runtime.mod("ida_moves")
    loc = _bookmark_template(runtime)
    if not ida_moves.bookmarks_t.erase(loc, slot, None):
        raise IdaOperationError(f"failed to delete bookmark slot {slot}")


def _write_bookmark(runtime: IdaRuntime, *, slot: int, identifier: str, comment: str) -> dict[str, object]:
    ida_idc = runtime.mod("ida_idc")
    ea = runtime.resolve_address(identifier)
    ida_idc.mark_position(ea, 0, 0, 0, slot, comment)
    state = _bookmark_state(runtime, slot)
    if not state["present"]:
        raise IdaOperationError(f"failed to set bookmark slot {slot}")
    return _bookmark_payload(
        slot=int(state["slot"]),
        present=bool(state["present"]),
        address=state["address"],  # type: ignore[arg-type]
        comment=state["comment"],  # type: ignore[arg-type]
        changed=True,
    )


def _parse_get(params: Mapping[str, Any]) -> BookmarkGetRequest:
    slot_value = params.get("slot")
    if slot_value in (None, ""):
        return BookmarkGetRequest()
    return BookmarkGetRequest(slot=_parse_slot(slot_value))


def _parse_set(params: Mapping[str, Any]) -> BookmarkSetRequest:
    return BookmarkSetRequest(
        slot=_parse_slot(params.get("slot")),
        identifier=_require_identifier(params.get("address"), label="address"),
        comment=str(params.get("comment") or ""),
    )


def _parse_add(params: Mapping[str, Any]) -> BookmarkAddRequest:
    return BookmarkAddRequest(
        identifier=_require_identifier(params.get("address"), label="address"),
        comment=str(params.get("comment") or ""),
    )


def _parse_delete(params: Mapping[str, Any]) -> BookmarkDeleteRequest:
    return BookmarkDeleteRequest(slot=_parse_slot(params.get("slot")))


def _get_bookmark(runtime: IdaRuntime, request: BookmarkGetRequest) -> dict[str, object]:
    if request.slot is None:
        return _bookmark_list(runtime)
    return _bookmark_state(runtime, _validate_slot(runtime, request.slot))


def _set_bookmark(runtime: IdaRuntime, request: BookmarkSetRequest) -> dict[str, object]:
    slot = _validate_slot(runtime, request.slot)
    return _write_bookmark(runtime, slot=slot, identifier=request.identifier, comment=request.comment)


def _add_bookmark(runtime: IdaRuntime, request: BookmarkAddRequest) -> dict[str, object]:
    slot = _first_free_slot(runtime)
    return _write_bookmark(runtime, slot=slot, identifier=request.identifier, comment=request.comment)


def _delete_bookmark(runtime: IdaRuntime, request: BookmarkDeleteRequest) -> dict[str, object]:
    slot = _validate_slot(runtime, request.slot)
    before = _bookmark_state(runtime, slot)
    if not before["present"]:
        return _bookmark_payload(
            slot=int(before["slot"]),
            present=bool(before["present"]),
            address=before["address"],  # type: ignore[arg-type]
            comment=before["comment"],  # type: ignore[arg-type]
            changed=False,
        )
    _erase_bookmark(runtime, slot)
    after = _bookmark_state(runtime, slot)
    return _bookmark_payload(
        slot=int(after["slot"]),
        present=bool(after["present"]),
        address=after["address"],  # type: ignore[arg-type]
        comment=after["comment"],  # type: ignore[arg-type]
        changed=True,
    )


def _run_bookmark_get(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _get_bookmark(runtime, _parse_get(params))


def _run_bookmark_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _set_bookmark(runtime, _parse_set(params))


def _run_bookmark_add(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _add_bookmark(runtime, _parse_add(params))


def _run_bookmark_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _delete_bookmark(runtime, _parse_delete(params))


def _capture_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_set(params)
    return _bookmark_state(runtime, _validate_slot(runtime, request.slot))


def _capture_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_delete(params)
    return _bookmark_state(runtime, _validate_slot(runtime, request.slot))


def _capture_add(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    del params
    return _bookmark_list(runtime)


def _restore_set_or_delete(
    runtime: IdaRuntime,
    params: Mapping[str, Any],
    before: dict[str, object],
    result: Any,
) -> None:
    slot = int(before["slot"])
    del params
    if before["present"]:
        if before["address"] is None:
            raise IdaOperationError(f"bookmark slot {slot} is present but has no saved address")
        _write_bookmark(
            runtime,
            slot=slot,
            identifier=str(before["address"]),
            comment="" if before["comment"] is None else str(before["comment"]),
        )
        return
    if isinstance(result, dict) and result.get("present"):
        _erase_bookmark(runtime, slot)


def _restore_added(
    runtime: IdaRuntime,
    params: Mapping[str, Any],
    before: dict[str, object],
    result: Any,
) -> None:
    del params, before
    if isinstance(result, dict) and result.get("present"):
        _erase_bookmark(runtime, int(result["slot"]))


BOOKMARK_OPS: dict[str, Op] = {
    "bookmark_get": Op(run=_run_bookmark_get),
    "bookmark_set": Op(
        run=_run_bookmark_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_set,
            capture_after=_capture_set,
            rollback=_restore_set_or_delete,
        ),
    ),
    "bookmark_add": Op(
        run=_run_bookmark_add,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_add,
            capture_after=_capture_add,
            rollback=_restore_added,
        ),
    ),
    "bookmark_delete": Op(
        run=_run_bookmark_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_delete,
            capture_after=_capture_delete,
            rollback=_restore_set_or_delete,
        ),
    ),
}


__all__ = [
    "BOOKMARK_OPS",
    "BookmarkAddRequest",
    "BookmarkDeleteRequest",
    "BookmarkGetRequest",
    "BookmarkSetRequest",
    "_first_free_bookmark_slot",
]
