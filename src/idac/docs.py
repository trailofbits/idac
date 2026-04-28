from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import skill_reference_source_dir, workspace_template_source_dir

_DOCS_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "CLI and operation help",
        (
            "cli",
            "troubleshooting",
            "targets",
        ),
    ),
    (
        "IDA reference",
        (
            "ida-cpp-type-details",
            "ida-set-types",
            "ida-advanced-type-annotations",
        ),
    ),
    (
        "Workflows",
        (
            "workflows",
            "class-recovery",
        ),
    ),
    (
        "Workspace resources",
        (
            "workspace",
            "templates",
        ),
    ),
)


@dataclass(frozen=True)
class DocsTopic:
    name: str
    title: str
    path: Path | None
    description: str
    aliases: tuple[str, ...] = ()


def _topic_map() -> dict[str, DocsTopic]:
    references = skill_reference_source_dir()
    workspace = workspace_template_source_dir()
    topics = [
        DocsTopic(
            "cli",
            "CLI Quick Reference",
            references / "cli.md",
            "Public command grammar, common reads, preview, batch, and output notes.",
            aliases=("commands", "quick-reference"),
        ),
        DocsTopic(
            "workflows",
            "Workflows",
            references / "workflows.md",
            "Safe mutation loop, batch usage, selector calibration, and readback.",
            aliases=("workflow", "mutation"),
        ),
        DocsTopic(
            "targets",
            "Targets And Backends",
            references / "targets-and-backends.md",
            "Choosing GUI vs idalib targets and resolving backend state.",
            aliases=("backends", "targets-and-backends"),
        ),
        DocsTopic(
            "troubleshooting",
            "Troubleshooting",
            references / "troubleshooting.md",
            "Bridge, backend, mutation, and stale-result troubleshooting.",
            aliases=("debug", "problems"),
        ),
        DocsTopic(
            "class-recovery",
            "Class Recovery",
            references / "class-recovery.md",
            "C++ class recovery workflow, naming rules, vtables, and verification.",
            aliases=("classes", "vtables"),
        ),
        DocsTopic(
            "ida-cpp-type-details",
            "IDA C++ Type Details",
            references / "ida-cpp-type-details.md",
            "IDA parser and decompiler expectations for C++ classes and vtables.",
            aliases=("cpp-types", "c++", "ida-cpp"),
        ),
        DocsTopic(
            "ida-set-types",
            "IDA Set Types",
            references / "ida-set-types.md",
            "IDA SetType behavior and type application details.",
            aliases=("set-types",),
        ),
        DocsTopic(
            "ida-advanced-type-annotations",
            "IDA Advanced Type Annotations",
            references / "ida-advanced-type-annotations.md",
            "IDA-specific type annotation syntax for recovered declarations.",
            aliases=("advanced-types", "annotations"),
        ),
        DocsTopic(
            "templates",
            "Reusable Templates",
            references / "templates" / "README.md",
            "Index of reusable batch, audit, and jq template files.",
            aliases=("template",),
        ),
        DocsTopic(
            "workspace",
            "Workspace Instructions",
            workspace / "AGENTS.md",
            "Default workspace structure and agent conventions.",
            aliases=("agents", "agents-md"),
        ),
    ]
    by_name: dict[str, DocsTopic] = {}
    for topic in topics:
        by_name[topic.name] = topic
        for alias in topic.aliases:
            by_name[alias] = topic
    return by_name


def docs_topics() -> list[DocsTopic]:
    seen: set[str] = set()
    unique: list[DocsTopic] = []
    topics = _topic_map()
    for _, names in _DOCS_GROUPS:
        for name in names:
            topic = topics[name]
            if topic.name in seen:
                continue
            seen.add(topic.name)
            unique.append(topic)
    for topic in topics.values():
        if topic.name in seen:
            continue
        seen.add(topic.name)
        unique.append(topic)
    return unique


def _topic_rows() -> list[str]:
    return [f"  {topic.name:<30} {topic.description}" for topic in docs_topics()]


def _grouped_topic_rows() -> list[str]:
    topics = _topic_map()
    lines: list[str] = []
    for group_name, names in _DOCS_GROUPS:
        lines.append(f"{group_name}:")
        for name in names:
            topic = topics[name]
            lines.append(f"  {topic.name:<30} {topic.description}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _index_text() -> str:
    lines = [
        "# idac docs",
        "",
        "Use `idac docs TOPIC` to print bundled idac and IDA guidance without needing a live IDA target.",
        "",
        "Start here:",
        "  idac docs cli",
        "  idac docs troubleshooting",
        "  idac docs ida-cpp-type-details",
        "  idac docs ida-set-types",
        "  idac docs ida-advanced-type-annotations",
        "  idac docs workflows",
        "  idac docs targets",
        "",
        "Common recovery topics:",
        "  idac docs class-recovery",
        "",
        "Reusable workspace material:",
        "  idac docs templates",
        "  idac docs workspace",
        "",
        "Available topics:",
        *_grouped_topic_rows(),
    ]
    return "\n".join(lines)


def _topic_payload(topic: DocsTopic) -> dict[str, Any]:
    if topic.path is None:
        text = _index_text()
        path = None
    else:
        text = topic.path.read_text(encoding="utf-8")
        path = str(topic.path)
    return {
        "topic": topic.name,
        "title": topic.title,
        "description": topic.description,
        "path": path,
        "text": text,
    }


def docs_payload(topic_name: str | None = None, *, list_only: bool = False, all_topics: bool = False) -> dict[str, Any]:
    if list_only:
        rows = [
            {
                "name": topic.name,
                "title": topic.title,
                "description": topic.description,
                "aliases": list(topic.aliases),
                "path": None if topic.path is None else str(topic.path),
            }
            for topic in docs_topics()
        ]
        return {
            "topic": "list",
            "topics": rows,
            "text": "\n".join(_grouped_topic_rows()),
        }

    if all_topics:
        parts = [_index_text()]
        for topic in docs_topics():
            if topic.path is None:
                continue
            parts.extend(["", "", f"# {topic.title}", "", topic.path.read_text(encoding="utf-8")])
        return {
            "topic": "all",
            "topics": [topic.name for topic in docs_topics()],
            "text": "\n".join(parts),
        }

    if topic_name in (None, ""):
        return {
            "topic": "index",
            "text": _index_text(),
        }

    topic = _topic_map().get(str(topic_name).strip())
    if topic is None:
        available = ", ".join(topic.name for topic in docs_topics())
        raise ValueError(f"unknown docs topic: {topic_name}. Available topics: {available}")
    return _topic_payload(topic)
