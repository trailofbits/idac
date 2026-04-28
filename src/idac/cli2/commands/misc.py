from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

from ...paths import (
    plugin_bootstrap_install_path,
    plugin_bootstrap_source_path,
    plugin_install_dir,
    plugin_runtime_package_install_dir,
    plugin_runtime_package_source_dir,
    plugin_source_dir,
    skill_install_dirs,
    skill_source_dir,
)
from ..argparse_utils import (
    add_command,
    add_context_options,
    add_install_options,
    add_output_options,
)
from ..commands.common import command_result, send_op
from ..result import CommandResult


def _install_path(source: Path, dest: Path, *, mode: str, force: bool, is_dir: bool) -> None:
    if not source.exists():
        raise OSError(f"source path is missing: {source}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if not force:
            raise OSError(f"destination already exists: {dest}")
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)
    if mode == "copy":
        if is_dir:
            shutil.copytree(source, dest)
        else:
            shutil.copy2(source, dest)
        return
    os.symlink(source, dest, target_is_directory=is_dir)


def _rename(args: argparse.Namespace) -> CommandResult:
    params = {"identifier": args.identifier, "new_name": args.new_name}
    return send_op(args, op="name_set", params=params, render_op="name_set")


def _reanalyze(args: argparse.Namespace) -> CommandResult:
    params: dict[str, object] = {"identifier": args.identifier}
    if args.end:
        params["end"] = args.end
    return send_op(args, op="reanalyze", params=params, render_op="reanalyze")


def _plugin_install(args: argparse.Namespace) -> CommandResult:
    package_source = plugin_source_dir()
    bootstrap_source = plugin_bootstrap_source_path()
    runtime_source = plugin_runtime_package_source_dir()
    custom_dest = args.dest
    package_dest = custom_dest or plugin_install_dir()
    bootstrap_dest = (
        package_dest.parent / plugin_bootstrap_install_path().name if custom_dest else plugin_bootstrap_install_path()
    )
    runtime_dest = package_dest.parent / runtime_source.name if custom_dest else plugin_runtime_package_install_dir()
    _install_path(package_source, package_dest, mode=args.mode, force=args.force, is_dir=True)
    _install_path(bootstrap_source, bootstrap_dest, mode=args.mode, force=args.force, is_dir=False)
    _install_path(runtime_source, runtime_dest, mode=args.mode, force=args.force, is_dir=True)
    return command_result(
        "plugin_install",
        {
            "installed": True,
            "mode": args.mode,
            "package_destination": str(package_dest),
            "bootstrap_destination": str(bootstrap_dest),
            "runtime_package_destination": str(runtime_dest),
        },
    )


def _skill_install(args: argparse.Namespace) -> CommandResult:
    source = skill_source_dir()
    custom_dest = args.dest
    destinations = [custom_dest] if custom_dest else skill_install_dirs(host=args.host)
    for dest in destinations:
        _install_path(source, dest, mode=args.mode, force=args.force, is_dir=True)
    return command_result(
        "skill_install",
        {
            "installed": True,
            "mode": args.mode,
            "source": str(source),
            "destinations": [str(dest) for dest in destinations],
        },
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "misc", help_text="Maintenance, setup, and utility commands")
    misc_subparsers = parser.add_subparsers(dest="misc_command")

    child = add_command(parser, misc_subparsers, "rename", help_text="Rename an item")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("new_name", help="Replacement name")
    child.set_defaults(
        run=_rename, context_policy="standard", allow_batch=False, allow_preview=False, _mutating_command=True
    )

    child = add_command(parser, misc_subparsers, "reanalyze", help_text="Re-run IDA analysis on a function or range")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("--end", help="Optional end address for range reanalysis")
    child.set_defaults(
        run=_reanalyze, context_policy="standard", allow_batch=False, allow_preview=False, _mutating_command=True
    )

    plugin_parser = add_command(parser, misc_subparsers, "plugin", help_text="Plugin operations")
    plugin_subparsers = plugin_parser.add_subparsers(dest="misc_plugin_command")
    child = add_command(plugin_parser, plugin_subparsers, "install", help_text="Install the GUI bridge plugin")
    add_output_options(child, default_format="json")
    add_install_options(child)
    child.add_argument("--dest", type=Path, help="Custom installation destination")
    child.set_defaults(
        run=_plugin_install, context_policy="none", allow_batch=False, allow_preview=False, _mutating_command=False
    )

    skill_parser = add_command(parser, misc_subparsers, "skill", help_text="Skill operations")
    skill_subparsers = skill_parser.add_subparsers(dest="misc_skill_command")
    child = add_command(skill_parser, skill_subparsers, "install", help_text="Install the bundled idac skill")
    add_output_options(child, default_format="json")
    add_install_options(child)
    child.add_argument("--dest", type=Path, help="Custom installation destination")
    child.add_argument("--host", choices=("claude", "codex", "both"), default="both", help="Install target host")
    child.set_defaults(
        run=_skill_install, context_policy="none", allow_batch=False, allow_preview=False, _mutating_command=False
    )
