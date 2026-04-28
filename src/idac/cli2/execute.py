from __future__ import annotations

import argparse

from .invocation import invocation_from_args, run_invocation


def prepare_args(args: argparse.Namespace) -> argparse.Namespace:
    invocation_from_args(args, argv=getattr(args, "_raw_argv", ()))
    return args


def execute_parsed(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser):
    invocation = invocation_from_args(args, argv=getattr(args, "_raw_argv", ()))
    return run_invocation(invocation)
