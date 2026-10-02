from __future__ import annotations

import re
from importlib import metadata
from typing import Any

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion

MINIMUM_PYTHON_VERSION = (3, 11)
MINIMUM_IDA_VERSION = (9, 4)

REMOTE_ENVIRONMENT_CODE = """
import importlib.metadata
import platform
import idaapi

result = {
    "ida_nexus": importlib.metadata.version("ida-nexus"),
    "ida_domain": importlib.metadata.version("ida-domain"),
    "ida": idaapi.get_kernel_version(),
    "python": platform.python_version(),
}
""".strip()


def runtime_requirements() -> dict[str, SpecifierSet]:
    """Read supported runtime versions from idac's installed package metadata."""
    return {
        requirement.name: requirement.specifier
        for dependency in metadata.requires("idac") or ()
        if (requirement := Requirement(dependency)).name in {"ida-nexus", "ida-domain"}
    }


def compatibility_mismatches(environment: dict[str, Any]) -> list[str]:
    """Describe every way a remote IDA runtime violates idac's supported stack."""

    mismatches: list[str] = []
    requirements = runtime_requirements()
    for distribution in ("ida-nexus", "ida-domain"):
        expected = requirements[distribution]
        try:
            supported = str(environment.get(distribution.replace("-", "_")) or "") in expected
        except InvalidVersion:
            supported = False
        if not supported:
            mismatches.append(f"{distribution} must satisfy {expected}")

    for label, value, minimum in (
        ("IDA", environment.get("ida"), MINIMUM_IDA_VERSION),
        ("IDA Python", environment.get("python"), MINIMUM_PYTHON_VERSION),
    ):
        match = re.fullmatch(r"\s*(\d+)(?:\.(\d+))?(?:\.\d+)*\s*", str(value or ""))
        parsed = tuple(int(part) for part in match.groups(default="0")) if match is not None else None
        if parsed is None or parsed < minimum:
            required = ".".join(str(part) for part in minimum)
            mismatches.append(f"{label} must be {required} or newer")
    return mismatches


__all__ = [
    "MINIMUM_IDA_VERSION",
    "MINIMUM_PYTHON_VERSION",
    "REMOTE_ENVIRONMENT_CODE",
    "compatibility_mismatches",
    "runtime_requirements",
]
