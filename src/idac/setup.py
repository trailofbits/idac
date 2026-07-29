from __future__ import annotations

import os
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .install_payload import copytree_ignore
from .paths import (
    plugin_bootstrap_source_path,
    plugin_install_dir,
    plugin_runtime_package_source_dir,
    plugin_source_dir,
    skill_install_dir,
    skill_install_dirs,
    skill_source_dir,
)

SetupAction = Literal["install", "update"]
SetupComponent = Literal["plugin", "skill"]
InstallMode = Literal["copy", "symlink"]
SkillAgent = Literal["claude", "codex", "both"]
SetupStatus = Literal["installed", "updated", "unchanged"]
SetupPhase = Literal["planned", "applied"]


class SetupValidationError(ValueError):
    pass


@dataclass(frozen=True)
class SetupRequest:
    action: SetupAction
    components: tuple[SetupComponent, ...] = ("plugin", "skill")
    agent: SkillAgent = "both"
    mode: InstallMode | None = None
    plugin_directory: Path | None = None
    skill_destination: Path | None = None


@dataclass(frozen=True)
class SetupTarget:
    component: SetupComponent
    name: str
    source: Path
    destination: Path
    is_dir: bool
    custom_destination: bool


@dataclass(frozen=True)
class PlannedTarget:
    target: SetupTarget
    mode: InstallMode
    status: SetupStatus


@dataclass(frozen=True)
class SetupPlan:
    request: SetupRequest
    targets: tuple[PlannedTarget, ...]

    @property
    def changed(self) -> bool:
        return any(item.status != "unchanged" for item in self.targets)

    @property
    def requires_confirmation(self) -> bool:
        return self.request.action == "update" and any(
            item.status == "updated" and item.target.custom_destination for item in self.targets
        )


@dataclass(frozen=True)
class PreparedTarget:
    planned: PlannedTarget
    staging_path: Path


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_path(path: Path) -> None:
    if not _path_exists(path):
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    shutil.rmtree(path)


def _temporary_sibling(path: Path, *, label: str) -> Path:
    token = uuid.uuid4().hex
    return path.parent / f".{path.name}.idac-{label}-{token}"


def _plugin_targets(custom_directory: Path | None) -> list[SetupTarget]:
    package_source = plugin_source_dir()
    bootstrap_source = plugin_bootstrap_source_path()
    runtime_source = plugin_runtime_package_source_dir()
    directory = custom_directory or plugin_install_dir().parent
    custom = custom_directory is not None
    return [
        SetupTarget("plugin", "bridge_package", package_source, directory / package_source.name, True, custom),
        SetupTarget("plugin", "bootstrap", bootstrap_source, directory / bootstrap_source.name, False, custom),
        SetupTarget("plugin", "runtime_package", runtime_source, directory / runtime_source.name, True, custom),
    ]


def _skill_target_name(destination: Path, *, agent: SkillAgent, custom: bool) -> str:
    if custom:
        return "skill_custom"
    matching_agents = [
        candidate for candidate in ("claude", "codex") if skill_install_dir(agent=candidate) == destination
    ]
    if matching_agents:
        return "skill_" + "_".join(matching_agents)
    return f"skill_{agent}"


def _skill_targets(agent: SkillAgent, custom_destination: Path | None) -> list[SetupTarget]:
    source = skill_source_dir()
    custom = custom_destination is not None
    destinations = [custom_destination] if custom_destination is not None else skill_install_dirs(agent=agent)
    return [
        SetupTarget(
            "skill",
            _skill_target_name(destination, agent=agent, custom=custom),
            source,
            destination,
            True,
            custom,
        )
        for destination in destinations
    ]


def build_setup_targets(request: SetupRequest) -> list[SetupTarget]:
    targets: list[SetupTarget] = []
    if "plugin" in request.components:
        targets.extend(_plugin_targets(request.plugin_directory))
    if "skill" in request.components:
        targets.extend(_skill_targets(request.agent, request.skill_destination))
    return targets


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _destination_views(path: Path) -> tuple[Path, ...]:
    lexical = _absolute_path(path)
    try:
        canonical_parent = lexical.parent.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SetupValidationError(f"failed to resolve destination parent for {path}: {exc}") from exc
    canonical = canonical_parent / lexical.name
    return (lexical,) if canonical == lexical else (lexical, canonical)


def _filesystem_is_case_insensitive(path: Path) -> bool:
    absolute = _absolute_path(path)
    existing = next((candidate for candidate in (absolute, *absolute.parents) if candidate.exists()), None)
    if sys.platform == "darwin" and existing is not None:
        try:
            # Python does not expose macOS's _PC_CASE_SENSITIVE name.
            return os.pathconf(existing, 11) == 0
        except (OSError, ValueError):
            pass
    existing_paths = (existing, *existing.parents) if existing is not None else ()
    for candidate in existing_paths:
        swapped = candidate.name.swapcase()
        if not swapped or swapped == candidate.name:
            continue
        try:
            return os.path.samefile(candidate, candidate.with_name(swapped))
        except OSError:
            continue
    return os.path.normcase("A") == os.path.normcase("a")


def _lexical_paths_overlap(first: Path, second: Path, *, ignore_case: bool = False) -> bool:
    first_parts = tuple(part.casefold() for part in first.parts) if ignore_case else first.parts
    second_parts = tuple(part.casefold() for part in second.parts) if ignore_case else second.parts
    return first_parts == second_parts[: len(first_parts)] or second_parts == first_parts[: len(second_parts)]


def _paths_overlap(first: Path, second: Path) -> bool:
    if _lexical_paths_overlap(first, second):
        return True
    if (_filesystem_is_case_insensitive(first) or _filesystem_is_case_insensitive(second)) and _lexical_paths_overlap(
        first, second, ignore_case=True
    ):
        return True
    if _same_existing_path(first, second):
        return True
    return any(_same_existing_path(first, parent) for parent in second.parents) or any(
        _same_existing_path(second, parent) for parent in first.parents
    )


def _same_existing_path(first: Path, second: Path) -> bool:
    if first.is_symlink() or second.is_symlink():
        return False
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _validate_targets(targets: list[SetupTarget], *, action: SetupAction) -> None:
    if not targets:
        raise SetupValidationError("setup requires at least one component")

    resolved_sources: list[tuple[SetupTarget, Path]] = []
    destination_views: list[tuple[SetupTarget, tuple[Path, ...]]] = []
    for target in targets:
        if not target.source.exists():
            raise OSError(f"source path is missing: {target.source}")
        if target.source.is_dir() != target.is_dir:
            raise OSError(f"source path has the wrong kind: {target.source}")
        resolved_sources.append((target, target.source.resolve(strict=True)))
        destination_views.append((target, _destination_views(target.destination)))

    for index, (target, views) in enumerate(destination_views):
        for previous, previous_views in destination_views[:index]:
            if any(_paths_overlap(view, previous_view) for view in views for previous_view in previous_views):
                raise SetupValidationError(
                    "setup destinations must not be equal or nested: "
                    f"{previous.name} ({previous.destination}) and {target.name} ({target.destination})"
                )

    for target, views in destination_views:
        for source_target, source in resolved_sources:
            if any(_paths_overlap(view, source) for view in views):
                raise SetupValidationError(
                    f"setup destination {target.name} ({target.destination}) must not overlap bundled source "
                    f"{source_target.name} ({source_target.source})"
                )

    if action == "install":
        existing = [target.destination for target in targets if _path_exists(target.destination)]
        if existing:
            rendered = ", ".join(str(path) for path in existing)
            raise SetupValidationError(
                f"setup destination already exists: {rendered} (use `idac setup update` to replace it)"
            )


def _existing_mode(path: Path) -> InstallMode | None:
    if path.is_symlink():
        return "symlink"
    if path.exists():
        return "copy"
    return None


def _resolved_modes(targets: list[SetupTarget], requested_mode: InstallMode | None) -> dict[Path, InstallMode]:
    if requested_mode is not None:
        return {target.destination: requested_mode for target in targets}

    component_modes: dict[SetupComponent, set[InstallMode]] = {"plugin": set(), "skill": set()}
    for target in targets:
        existing = _existing_mode(target.destination)
        if existing is not None:
            component_modes[target.component].add(existing)

    modes: dict[Path, InstallMode] = {}
    for target in targets:
        existing = _existing_mode(target.destination)
        if existing is not None:
            modes[target.destination] = existing
            continue
        observed = component_modes[target.component]
        modes[target.destination] = next(iter(observed)) if len(observed) == 1 else "symlink"
    return modes


def _symlink_matches_source(target: SetupTarget) -> bool:
    if not target.destination.is_symlink():
        return False
    try:
        return target.destination.resolve(strict=True) == target.source.resolve(strict=True)
    except OSError:
        return False


def plan_setup(request: SetupRequest) -> SetupPlan:
    targets = build_setup_targets(request)
    _validate_targets(targets, action=request.action)
    modes = _resolved_modes(targets, request.mode)

    planned: list[PlannedTarget] = []
    for target in targets:
        mode = modes[target.destination]
        existed = _path_exists(target.destination)
        if request.action == "update" and mode == "symlink" and _symlink_matches_source(target):
            status: SetupStatus = "unchanged"
        else:
            status = "updated" if existed else "installed"
        planned.append(
            PlannedTarget(
                target=target,
                mode=mode,
                status=status,
            )
        )
    return SetupPlan(request=request, targets=tuple(planned))


def setup_result(
    plan: SetupPlan,
    *,
    phase: SetupPhase,
    cleanup_warnings: list[str] | None = None,
) -> dict[str, object]:
    warnings = list(cleanup_warnings or [])
    target_results = [
        {
            "component": item.target.component,
            "name": item.target.name,
            "source": str(item.target.source),
            "destination": str(item.target.destination),
            "mode": item.mode,
            "status": item.status,
        }
        for item in plan.targets
    ]
    target_results.sort(key=lambda item: (str(item["component"]), str(item["name"])))
    return {
        "phase": phase,
        "action": plan.request.action,
        "components": list(plan.request.components),
        "changed": plan.changed,
        "requires_confirmation": phase == "planned" and plan.requires_confirmation,
        "ida_reload_recommended": phase == "applied"
        and any(item.target.component == "plugin" and item.status != "unchanged" for item in plan.targets),
        "cleanup_warnings": warnings,
        "targets": target_results,
    }


def _stage_target(planned: PlannedTarget) -> Path:
    target = planned.target
    target.destination.parent.mkdir(parents=True, exist_ok=True)
    staging_path = _temporary_sibling(target.destination, label="stage")
    try:
        if planned.mode == "copy":
            if target.is_dir:
                shutil.copytree(target.source, staging_path, ignore=copytree_ignore)
            else:
                shutil.copy2(target.source, staging_path)
        else:
            os.symlink(target.source, staging_path, target_is_directory=target.is_dir)
    except BaseException:
        _cleanup_paths([staging_path], label="staging path")
        raise
    return staging_path


def _cleanup_paths(paths: list[Path], *, label: str) -> list[str]:
    warnings: list[str] = []
    for path in paths:
        try:
            _remove_path(path)
        except OSError as exc:
            warnings.append(f"could not remove setup {label} {path}: {exc or exc.__class__.__name__}")
    return warnings


def _rollback(
    prepared: list[PreparedTarget],
    *,
    committed: set[Path],
    backups: dict[Path, Path],
) -> list[str]:
    errors: list[str] = []
    for item in reversed(prepared):
        destination = item.planned.target.destination
        backup = backups.get(destination)
        try:
            if destination in committed:
                _remove_path(destination)
            if backup is not None and _path_exists(backup):
                if _path_exists(destination):
                    _remove_path(destination)
                os.replace(backup, destination)
        except BaseException as exc:
            errors.append(f"{destination}: {exc or exc.__class__.__name__}")
    return errors


def _commit(prepared: list[PreparedTarget]) -> list[str]:
    committed: set[Path] = set()
    backups: dict[Path, Path] = {}
    cleanup_warnings: list[str] = []
    try:
        for item in prepared:
            destination = item.planned.target.destination
            if _path_exists(destination):
                backup = _temporary_sibling(destination, label="backup")
                backups[destination] = backup
                os.replace(destination, backup)
            committed.add(destination)
            os.replace(item.staging_path, destination)
    except BaseException as exc:
        rollback_errors = _rollback(prepared, committed=committed, backups=backups)
        if isinstance(exc, OSError):
            suffix = f"; rollback errors: {'; '.join(rollback_errors)}" if rollback_errors else ""
            raise OSError(f"failed to commit setup transaction: {exc}{suffix}") from exc
        if rollback_errors:
            detail = f"setup rollback errors: {'; '.join(rollback_errors)}"
            add_note = getattr(exc, "add_note", None)
            if add_note is not None:
                add_note(detail)
            else:
                exc.args = (f"{exc or exc.__class__.__name__}; {detail}",)
        raise
    finally:
        cleanup_warnings.extend(_cleanup_paths([item.staging_path for item in prepared], label="staging path"))

    cleanup_warnings.extend(_cleanup_paths(list(backups.values()), label="backup"))
    return cleanup_warnings


def apply_setup(plan: SetupPlan) -> dict[str, object]:
    prepared: list[PreparedTarget] = []
    try:
        for planned in plan.targets:
            if planned.status == "unchanged":
                continue
            prepared.append(PreparedTarget(planned=planned, staging_path=_stage_target(planned)))
    except BaseException:
        _cleanup_paths([item.staging_path for item in prepared], label="staging path")
        raise

    cleanup_warnings = _commit(prepared)
    return setup_result(plan, phase="applied", cleanup_warnings=cleanup_warnings)
