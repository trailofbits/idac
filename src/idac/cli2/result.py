from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandResult:
    render_op: str
    value: Any
    exit_code: int = 0
    warnings: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
