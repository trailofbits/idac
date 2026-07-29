from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from ...setup import (
    InstallMode,
    SetupAction,
    SetupComponent,
    SetupPlan,
    SetupRequest,
    SkillAgent,
    apply_setup,
    plan_setup,
    setup_result,
)
from ..argparse_utils import add_command, add_output_options
from ..commands.common import command_result
from ..errors import CliUserError
from ..renderers import render_setup
from ..result import CommandResult


def _setup_request(args: argparse.Namespace) -> SetupRequest:
    components = cast(
        tuple[SetupComponent, ...],
        (args.component,) if args.component is not None else ("plugin", "skill"),
    )
    if args.plugin_dir is not None and "plugin" not in components:
        raise CliUserError("--plugin-dir requires the plugin component")
    if args.skill_dest is not None and "skill" not in components:
        raise CliUserError("--skill-dest requires the skill component")
    if args.agent is not None and "skill" not in components:
        raise CliUserError("--agent requires the skill component")
    if args.agent is not None and args.skill_dest is not None:
        raise CliUserError("--agent cannot be combined with --skill-dest because a custom destination has no agent")
    return SetupRequest(
        action=cast(SetupAction, args.setup_command),
        components=components,
        agent=cast(SkillAgent, args.agent or "both"),
        mode=cast(InstallMode | None, args.mode),
        plugin_directory=args.plugin_dir,
        skill_destination=args.skill_dest,
    )


def _confirmation_lines(plan: SetupPlan) -> list[str]:
    return render_setup(setup_result(plan, phase="planned")).splitlines()


def _confirm_setup_update(plan: SetupPlan) -> None:
    for line in _confirmation_lines(plan):
        print(line, file=sys.stderr)
    if not sys.stdin.isatty():
        raise CliUserError(
            "setup update requires confirmation in an interactive terminal; "
            "inspect with --dry-run and rerun with --force"
        )
    print("Continue? [y/N] ", end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline().strip().lower()
    if answer not in {"y", "yes"}:
        raise CliUserError("setup update cancelled")


def _run_setup(args: argparse.Namespace) -> CommandResult:
    try:
        plan = plan_setup(_setup_request(args))
    except ValueError as exc:
        raise CliUserError(str(exc)) from exc
    if args.dry_run:
        return command_result("setup", setup_result(plan, phase="planned"))
    if plan.requires_confirmation and not args.force:
        _confirm_setup_update(plan)

    value = apply_setup(plan)
    warnings: list[str] = []
    cleanup_warnings = value.get("cleanup_warnings")
    if isinstance(cleanup_warnings, list):
        warnings.extend(str(item) for item in cleanup_warnings)
    if value.get("ida_reload_recommended"):
        warnings.append(
            "if IDA is running, reload the idac bridge plugin or restart IDA to use the current bridge package"
        )
    return command_result("setup", value, warnings=warnings)


def _add_setup_options(parser: argparse.ArgumentParser, *, is_update: bool) -> None:
    add_output_options(parser, default_format="text")
    parser.add_argument(
        "--component",
        choices=("plugin", "skill"),
        help="Limit setup to one component (default: both)",
    )
    parser.add_argument(
        "--agent",
        choices=("claude", "codex", "both"),
        default=None,
        help="Agent skill target (default: both); cannot be combined with --skill-dest",
    )
    parser.add_argument(
        "--mode",
        choices=("copy", "symlink"),
        default=None,
        help=(
            "Installation mode (default: preserve existing mode; symlink for new targets)"
            if is_update
            else "Installation mode (default: symlink)"
        ),
    )
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        help="Custom directory for GUI bridge plugin files",
    )
    parser.add_argument("--skill-dest", type=Path, help="Custom skill destination")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show the setup plan without changing files",
    )
    if is_update:
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation when replacing custom destinations",
        )
    parser.set_defaults(
        run=_run_setup,
        force=False,
        context_policy="none",
        allow_batch=False,
        allow_preview=False,
        _mutating_command=False,
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "setup", help_text="Install or update bundled integrations")
    setup_subparsers = parser.add_subparsers(dest="setup_command")

    child = add_command(
        parser,
        setup_subparsers,
        "install",
        help_text="Install the GUI bridge and agent skills",
    )
    _add_setup_options(child, is_update=False)

    child = add_command(
        parser,
        setup_subparsers,
        "update",
        help_text="Update bundled integrations from this idac installation",
    )
    _add_setup_options(child, is_update=True)
