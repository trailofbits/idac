from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import run_nexus, run_nexus_json, run_nexus_text


def test_nexus_ctree_dump(idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path) -> None:
    database = copy_database(tiny_database)

    result = run_nexus_json(idac_cmd, idac_env, database, "ctree", "main")

    assert isinstance(result, dict)
    assert result["level"] == "ctree"
    assert result["function"] == "main"
    assert "asg" in result["text"]
    assert isinstance(result["nodes"], list)
    assert any(item["op"] == "call" for item in result["nodes"] if isinstance(item, dict))


def test_nexus_microcode_dump(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_path = tmp_path / "microcode.json"
    proc = run_nexus(
        idac_cmd,
        idac_env,
        database,
        "ctree",
        "main",
        "--level",
        "micro",
        "--maturity",
        "generated",
        "--out",
        str(out_path),
        use_json=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    result = json.loads(out_path.read_text(encoding="utf-8"))

    assert isinstance(result, dict)
    assert result["level"] == "micro"
    assert result["maturity"] == "generated"
    assert isinstance(result["lines"], list)
    assert any("BLOCK" in line or "mov" in line for line in result["lines"])


def test_nexus_microcode_includes_function_tail(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    created = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        """
import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_ua
entry = 0x200000000
tail = entry + 0x20
assert ida_segment.add_segm(0, entry, entry + 0x100, 'split_function_test', 'CODE')
ida_segment.getseg(entry).bitness = 2
ida_bytes.patch_bytes(entry, bytes.fromhex('08000014'))  # b tail
ida_bytes.patch_bytes(tail, bytes.fromhex('40058052c0035fd6'))  # mov w0, #42; ret
assert ida_ua.create_insn(entry) == 4
assert ida_ua.create_insn(tail) == 4
assert ida_ua.create_insn(tail + 4) == 4
assert ida_funcs.add_func(entry, entry + 4)
assert ida_funcs.append_func_tail(ida_funcs.get_func(entry), tail, tail + 8)
assert ida_name.set_name(entry, 'split_function_test')
ida_auto.auto_wait()
result = list(idautils.Chunks(entry))
""",
    )
    assert created["result"] == [[0x200000000, 0x200000004], [0x200000020, 0x200000028]]
    decompiled = run_nexus_text(idac_cmd, idac_env, database, "decompile", "split_function_test", "--f5")
    assert "return 42" in decompiled

    microcode = run_nexus_json(
        idac_cmd, idac_env, database, "ctree", "split_function_test", "--level", "micro", "--maturity", "generated"
    )
    assert "200000020" in microcode["text"]
    assert "200000024" in microcode["text"]
    assert "#0x2A" in microcode["text"]
