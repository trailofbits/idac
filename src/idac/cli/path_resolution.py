from __future__ import annotations

import argparse
import contextlib
from pathlib import Path

from .errors import CliUserError


def resolve_relative_paths(args: argparse.Namespace, *, base_dir: Path) -> None:
    for key, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            setattr(args, key, base_dir / value)


def reject_output_aliases(
    output_path: Path | None,
    protected_paths: list[tuple[str, Path | None]],
    *,
    option_label: str,
) -> None:
    """Reject output paths that resolve to protected files, including links."""

    if output_path is None:
        return
    resolved_output = output_path.expanduser().resolve(strict=False)
    for protected_label, protected_path in protected_paths:
        if protected_path is None:
            continue
        candidate = protected_path.expanduser()
        aliases = resolved_output == candidate.resolve(strict=False)
        if not aliases:
            with contextlib.suppress(OSError):
                aliases = output_path.samefile(candidate)
        if aliases:
            raise CliUserError(f"{option_label} must not overwrite the {protected_label}: {protected_path}")
