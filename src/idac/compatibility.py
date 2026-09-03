from __future__ import annotations

import re
from typing import Any

IDA_NEXUS_VERSION = "0.7.0"
IDA_DOMAIN_VERSION = "0.5.1"
IDA_HCLI_VERSION = "0.20.1"
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


def compatibility_mismatches(environment: dict[str, Any]) -> list[str]:
    """Describe every way a remote IDA runtime violates idac's supported stack."""

    mismatches: list[str] = []
    if environment.get("ida_nexus") != IDA_NEXUS_VERSION:
        mismatches.append(f"ida-nexus must be exactly {IDA_NEXUS_VERSION}")
    if environment.get("ida_domain") != IDA_DOMAIN_VERSION:
        mismatches.append(f"ida-domain must be exactly {IDA_DOMAIN_VERSION}")

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
    "IDA_DOMAIN_VERSION",
    "IDA_HCLI_VERSION",
    "IDA_NEXUS_VERSION",
    "MINIMUM_IDA_VERSION",
    "MINIMUM_PYTHON_VERSION",
    "REMOTE_ENVIRONMENT_CODE",
    "compatibility_mismatches",
]
