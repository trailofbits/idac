from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import skill_reference_source_dir, skill_source_dir, workspace_template_source_dir


@dataclass(frozen=True)
class DocsTopic:
    name: str
    title: str
    path: Path
    description: str
    aliases: tuple[str, ...] = ()
    extra_paths: tuple[Path, ...] = ()


_REFERENCES = skill_reference_source_dir()
_SKILL = skill_source_dir()
_WORKSPACE = workspace_template_source_dir()

_DOCS_GROUPS: tuple[tuple[str, tuple[DocsTopic, ...]], ...] = (
    (
        "Start here",
        (
            DocsTopic(
                "guide",
                "Agent Guide",
                _SKILL / "SKILL.md",
                "Start here: critical defaults, task routing, and reference index.",
                aliases=("start", "agents-guide", "skill"),
            ),
        ),
    ),
    (
        "CLI and operation help",
        (
            DocsTopic(
                "cli",
                "CLI Quick Reference",
                _REFERENCES / "cli.md",
                "Public command grammar, common reads, preview, batch, and output notes.",
                aliases=("commands", "quick-reference"),
            ),
            DocsTopic(
                "troubleshooting",
                "Troubleshooting",
                _REFERENCES / "troubleshooting.md",
                "Nexus selection, runtime compatibility, mutation, and timeout troubleshooting.",
                aliases=("debug", "problems"),
            ),
            DocsTopic(
                "targets",
                "Targets And Backends",
                _REFERENCES / "targets-and-backends.md",
                "Choosing path or record-ID Nexus contexts and resolving discovery state.",
                aliases=("backends", "targets-and-backends"),
            ),
        ),
    ),
    (
        "IDA reference",
        (
            DocsTopic(
                "ida-cpp-type-details",
                "IDA C++ Type Details",
                _REFERENCES / "ida-cpp-type-details.md",
                "IDA parser and decompiler expectations for C++ classes and vtables.",
                aliases=("cpp-types", "c++", "ida-cpp"),
            ),
            DocsTopic(
                "ida-set-types",
                "IDA Type Declaration Syntax",
                _REFERENCES / "ida-set-types.md",
                "IDA C declaration syntax: calling conventions, usercall locations, and attribute/type keywords.",
                aliases=("set-types",),
            ),
            DocsTopic(
                "ida-advanced-type-annotations",
                "IDA Advanced Type Annotations",
                _REFERENCES / "ida-advanced-type-annotations.md",
                "IDA-specific type annotation syntax for recovered declarations.",
                aliases=("advanced-types", "annotations"),
            ),
        ),
    ),
    (
        "Workflows",
        (
            DocsTopic(
                "workflows",
                "Workflows",
                _REFERENCES / "workflows.md",
                "Safe mutation loop, batch usage, selector calibration, and readback.",
                aliases=("workflow", "mutation"),
            ),
            DocsTopic(
                "class-recovery",
                "Class Recovery",
                _REFERENCES / "class-recovery.md",
                "C++ class recovery workflow, naming rules, vtables, and verification.",
                aliases=("classes", "vtables"),
            ),
        ),
    ),
    (
        "Workspace resources",
        (
            DocsTopic(
                "workspace",
                "Workspace Instructions",
                _WORKSPACE / "AGENTS.md",
                "Default workspace structure and agent conventions.",
                aliases=("agents", "agents-md"),
            ),
            DocsTopic(
                "templates",
                "Reusable Templates",
                _REFERENCES / "templates" / "README.md",
                "Reusable batch, audit, and jq template files, printed in full.",
                aliases=("template",),
                extra_paths=(
                    _REFERENCES / "templates" / "checkpoint-note.md",
                    _REFERENCES / "templates" / "prototype-pass.idac",
                    _REFERENCES / "templates" / "rename-pass.idac",
                    _REFERENCES / "templates" / "locals-jq-snippets.sh",
                ),
            ),
        ),
    ),
)

_TOPICS_BY_NAME = {
    name: topic for _, topics in _DOCS_GROUPS for topic in topics for name in (topic.name, *topic.aliases)
}


def docs_topics() -> list[DocsTopic]:
    return [topic for _, topics in _DOCS_GROUPS for topic in topics]


def _grouped_topic_rows() -> list[str]:
    lines: list[str] = []
    for group_name, topics in _DOCS_GROUPS:
        lines.append(f"{group_name}:")
        for topic in topics:
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
        "  idac docs guide",
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


def _strip_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    _, sep, rest = text.partition("\n---\n")
    if not sep:
        return text
    return rest.lstrip()


def _topic_payload(topic: DocsTopic) -> dict[str, Any]:
    text = _strip_frontmatter(topic.path.read_text(encoding="utf-8"))
    for extra in topic.extra_paths:
        body = extra.read_text(encoding="utf-8").rstrip()
        if extra.suffix != ".md":
            body = f"```\n{body}\n```"
        text = f"{text.rstrip()}\n\n---\n\n`{extra.name}`:\n\n{body}\n"
    return {
        "topic": topic.name,
        "title": topic.title,
        "description": topic.description,
        "path": str(topic.path),
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
                "path": str(topic.path),
            }
            for topic in docs_topics()
        ]
        return {
            "topic": "list",
            "topics": rows,
            "text": "\n".join(_grouped_topic_rows()),
        }

    if all_topics:
        topics = docs_topics()
        parts = [_index_text()]
        for topic in topics:
            parts.extend(["", "", f"# {topic.title}", "", _topic_payload(topic)["text"]])
        return {
            "topic": "all",
            "topics": [topic.name for topic in topics],
            "text": "\n".join(parts),
        }

    if topic_name in (None, ""):
        return {
            "topic": "index",
            "text": _index_text(),
        }

    topic = _TOPICS_BY_NAME.get(str(topic_name).strip())
    if topic is None:
        available = ", ".join(topic.name for topic in docs_topics())
        raise ValueError(f"unknown docs topic: {topic_name}. Available topics: {available}")
    return _topic_payload(topic)
