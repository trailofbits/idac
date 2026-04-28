from __future__ import annotations

import argparse
from pathlib import Path


def resolve_relative_paths(args: argparse.Namespace, *, base_dir: Path) -> None:
    for key, value in vars(args).items():
        if isinstance(value, Path) and not value.is_absolute():
            setattr(args, key, base_dir / value)
