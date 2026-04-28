from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from idac.ops.families.classes import _raw_vtable_dump, _vtable_members


class FakeIdaIda:
    def __init__(self, bits: int) -> None:
        self._bits = bits

    def inf_is_64bit(self) -> bool:
        return self._bits == 64

    def inf_is_32bit_exactly(self) -> bool:
        return self._bits == 32


class FakeIdaBytes:
    def __init__(self, values: dict[int, int], code_targets: set[int]) -> None:
        self._values = values
        self._code_targets = code_targets

    def get_qword(self, ea: int) -> int:
        return self._values.get(ea, 0)

    def get_wide_dword(self, ea: int) -> int:
        return self._values.get(ea, 0) & 0xFFFFFFFF

    def get_wide_word(self, ea: int) -> int:
        return self._values.get(ea, 0) & 0xFFFF

    def get_flags(self, ea: int) -> int:
        return 1 if ea in self._code_targets else 0

    def is_code(self, flags: int) -> bool:
        return bool(flags)


class FakeIdaFuncs:
    def __init__(self, code_targets: set[int]) -> None:
        self._code_targets = code_targets

    def get_func(self, ea: int) -> object | None:
        return object() if ea in self._code_targets else None


class FakeIdaName:
    def __init__(self, names: dict[int, str]) -> None:
        self._names = names

    def get_name(self, ea: int) -> str:
        return self._names.get(ea, "")


class FakeIdaTypeinf:
    @staticmethod
    def udt_type_data_t() -> list[Any]:
        return []


@dataclass
class FakeMemberType:
    text: str

    def dstr(self) -> str:
        return self.text


@dataclass
class FakeMember:
    offset: int
    name: str
    type: FakeMemberType
    cmt: str = ""


class FakeVtableTif:
    def __init__(self, members: list[FakeMember]) -> None:
        self._members = members

    def get_udt_details(self, udt: list[Any]) -> bool:
        udt.extend(self._members)
        return True


class FakeRuntime:
    def __init__(
        self,
        bits: int,
        *,
        values: dict[int, int] | None = None,
        names: dict[int, str] | None = None,
    ) -> None:
        code_targets = {ea for ea, name in (names or {}).items() if name.startswith("sub_")}
        self._mods = {
            "ida_ida": FakeIdaIda(bits),
            "ida_bytes": FakeIdaBytes(values or {}, code_targets),
            "ida_funcs": FakeIdaFuncs(code_targets),
            "ida_name": FakeIdaName(names or {}),
            "ida_typeinf": FakeIdaTypeinf(),
        }

    def mod(self, name: str) -> Any:
        return self._mods[name]

    @staticmethod
    def member_has(member, attr: str) -> bool:
        return bool(getattr(member, attr, lambda: False)())

    def udt_members(self, tif):
        udt = self.mod("ida_typeinf").udt_type_data_t()
        return udt if tif.get_udt_details(udt) else ()

    def pointer_size(self) -> int:
        ida_ida = self.mod("ida_ida")
        if ida_ida.inf_is_64bit():
            return 8
        if ida_ida.inf_is_32bit_exactly():
            return 4
        return 2

    def pointer_bits(self) -> int:
        return self.pointer_size() * 8

    def read_pointer(self, ea: int) -> int:
        ida_bytes = self.mod("ida_bytes")
        width = self.pointer_size()
        if width == 8:
            return int(ida_bytes.get_qword(ea))
        if width == 4:
            return int(ida_bytes.get_wide_dword(ea))
        return int(ida_bytes.get_wide_word(ea))

    def vtable_slot(self, offset_bits: int) -> int:
        return int(offset_bits) // self.pointer_bits()

    def resolve_address(self, identifier: str) -> int:
        return int(identifier, 0)

    def demangle_name(self, name: str) -> str | None:
        return name if name else None

    def tinfo_decl(self, tif, *, name=None, multi=True) -> str:
        return tif.dstr()

    def get_named_type(self, name: str):
        raise AssertionError(f"unexpected type lookup: {name}")

    def find_named_type(self, name: str):
        return None


def test_vtable_members_use_pointer_width_for_slot_numbers() -> None:
    runtime = FakeRuntime(32)
    tif = FakeVtableTif(
        [
            FakeMember(offset=0, name="scalar_del", type=FakeMemberType("void (*)()")),
            FakeMember(offset=32, name="vector_del", type=FakeMemberType("void (*)()")),
        ]
    )

    members = _vtable_members(runtime, tif)

    assert runtime.pointer_bits() == 32
    assert [member["slot"] for member in members] == [0, 1]


def test_raw_vtable_dump_reads_32bit_entries_with_4byte_stride() -> None:
    runtime = FakeRuntime(
        32,
        values={
            0x1000: 0,
            0x1004: 0x2000,
            0x1008: 0x3000,
            0x100C: 0x4000,
            0x1010: 0,
        },
        names={
            0x1000: "__ZTV3Foo",
            0x2000: "__ZTI3Foo",
            0x3000: "sub_3000",
            0x4000: "sub_4000",
        },
    )

    payload = _raw_vtable_dump(runtime, "0x1000", slot_limit=4)

    assert payload["abi"] == "itanium"
    assert payload["slot_address"] == "0x1008"
    assert payload["slot_count"] == 2
    assert payload["stop_reason"] == "null_target"
    assert payload["members"][0]["entry_address"] == "0x1008"
    assert payload["members"][1]["entry_address"] == "0x100c"
    assert [member["target"] for member in payload["members"]] == ["0x3000", "0x4000"]


def test_raw_vtable_dump_stops_before_adjacent_rtti_symbol() -> None:
    runtime = FakeRuntime(
        64,
        values={
            0x1000: 0,
            0x1008: 0x2000,
            0x1010: 0x3000,
            0x1018: 0x4000,
            0x1020: 0x5000,
        },
        names={
            0x1000: "__ZTV3Foo",
            0x2000: "__ZTI3Foo",
            0x3000: "sub_3000",
            0x4000: "sub_4000",
            0x5000: "__ZTI3Bar",
        },
    )

    payload = _raw_vtable_dump(runtime, "0x1000", slot_limit=4)

    assert payload["abi"] == "itanium"
    assert payload["slot_count"] == 2
    assert payload["stop_reason"] == "rtti_boundary"
    assert [member["target"] for member in payload["members"]] == ["0x3000", "0x4000"]
