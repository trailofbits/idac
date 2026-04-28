from __future__ import annotations

from pathlib import Path

from tests.helpers import preview_round_trip_cli2, run_idalib_json


def test_bookmark_list_returns_all_live_slots_only(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "5", "main", "--comment", "entry point")
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "2", "add", "--comment", "helper")

    result = run_idalib_json(idac_cmd, idac_env, database, "bookmark", "list")

    assert isinstance(result, dict)
    assert result["count"] == 2
    assert result["bookmarks"] == [
        {
            "slot": 2,
            "present": True,
            "address": "0x1000004b0",
            "comment": "helper",
        },
        {
            "slot": 5,
            "present": True,
            "address": "0x100000460",
            "comment": "entry point",
        },
    ]


def test_bookmark_show_reports_empty_slot(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    result = run_idalib_json(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "bookmark",
        "show",
        "5",
    )

    assert result == {
        "slot": 5,
        "present": False,
        "address": None,
        "comment": None,
    }


def test_bookmark_add_uses_lowest_free_slot(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "2", "add", "--comment", "helper")
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "5", "main", "--comment", "entry point")

    added = run_idalib_json(idac_cmd, idac_env, database, "bookmark", "add", "main", "--comment", "auto slot")

    assert added == {
        "slot": 0,
        "present": True,
        "address": "0x100000460",
        "comment": "auto slot",
        "changed": True,
    }
    assert run_idalib_json(idac_cmd, idac_env, database, "bookmark", "show", "0") == {
        "slot": 0,
        "present": True,
        "address": "0x100000460",
        "comment": "auto slot",
    }


def test_bookmark_set_preview_then_persist_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["bookmark", "show", "5"],
        persist_args=["bookmark", "set", "5", "main", "--comment", "entry point"],
    )

    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]

    assert preview["before"] == {
        "slot": 5,
        "present": False,
        "address": None,
        "comment": None,
    }
    assert preview["after"] == {
        "slot": 5,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
    }
    assert after_preview == preview["before"]
    assert persisted == {
        "slot": 5,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
        "changed": True,
    }
    assert after_persist == preview["after"]


def test_bookmark_set_preview_then_persist_overwrites_existing_slot(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "5", "add", "--comment", "helper")

    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["bookmark", "show", "5"],
        persist_args=["bookmark", "set", "5", "main", "--comment", "entry point"],
    )

    preview = result["preview"]
    assert preview["before"] == {
        "slot": 5,
        "present": True,
        "address": "0x1000004b0",
        "comment": "helper",
    }
    assert preview["after"] == {
        "slot": 5,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
    }
    assert result["after_preview"] == preview["before"]
    assert result["persisted"] == {
        "slot": 5,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
        "changed": True,
    }
    assert result["after_persist"] == preview["after"]


def test_bookmark_add_preview_then_persist_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["bookmark", "list"],
        persist_args=["bookmark", "add", "main", "--comment", "entry point"],
    )

    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]

    assert preview["before"] == {"bookmarks": [], "count": 0}
    assert preview["after"] == {
        "bookmarks": [
            {
                "slot": 0,
                "present": True,
                "address": "0x100000460",
                "comment": "entry point",
            }
        ],
        "count": 1,
    }
    assert after_preview == preview["before"]
    assert persisted == {
        "slot": 0,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
        "changed": True,
    }
    assert after_persist == preview["after"]


def test_bookmark_delete_empty_slot_is_a_noop(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    deleted = run_idalib_json(idac_cmd, idac_env, database, "bookmark", "delete", "5")

    assert deleted == {
        "slot": 5,
        "present": False,
        "address": None,
        "comment": None,
        "changed": False,
    }


def test_bookmark_delete_preview_then_persist_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "bookmark", "set", "5", "main", "--comment", "entry point")

    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["bookmark", "show", "5"],
        persist_args=["bookmark", "delete", "5"],
    )

    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]

    assert preview["before"] == {
        "slot": 5,
        "present": True,
        "address": "0x100000460",
        "comment": "entry point",
    }
    assert preview["after"] == {
        "slot": 5,
        "present": False,
        "address": None,
        "comment": None,
    }
    assert after_preview == preview["before"]
    assert persisted == {
        "slot": 5,
        "present": False,
        "address": None,
        "comment": None,
        "changed": True,
    }
    assert after_persist == preview["after"]
