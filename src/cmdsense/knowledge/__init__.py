"""Data-driven command knowledge base for CmdSense (macOS / POSIX developer commands)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CommandSpec:
    """Rich metadata for a single CLI command or shell built-in."""

    name: str
    category: str
    summary: str
    expected_output: str
    side_effects: str
    security: str
    macos_notes: str = "Standard macOS / POSIX behavior."
    flags: dict[str, str] = field(default_factory=dict)
    subcommands: dict[str, str] = field(default_factory=dict)
    flags_taking_value: frozenset[str] = field(default_factory=frozenset)
    word_flags: bool = (
        False  # True for commands like `find` that use single-dash word flags (-name)
    )


def _load_kb() -> dict[str, CommandSpec]:
    from cmdsense.knowledge.dev_tools import DEV_TOOLS_SPECS
    from cmdsense.knowledge.filesystem import FILESYSTEM_SPECS
    from cmdsense.knowledge.macos_shell import MACOS_SHELL_SPECS
    from cmdsense.knowledge.process_network import PROCESS_NETWORK_SPECS
    from cmdsense.knowledge.text_search import TEXT_SEARCH_SPECS

    combined: dict[str, CommandSpec] = {}
    for group in (
        FILESYSTEM_SPECS,
        TEXT_SEARCH_SPECS,
        PROCESS_NETWORK_SPECS,
        DEV_TOOLS_SPECS,
        MACOS_SHELL_SPECS,
    ):
        for spec in group:
            combined[spec.name] = spec
    return combined


COMMANDS_KB: dict[str, CommandSpec] = {}


def get_kb() -> dict[str, CommandSpec]:
    """Return the lazily-populated command knowledge base mapping."""
    if not COMMANDS_KB:
        COMMANDS_KB.update(_load_kb())
    return COMMANDS_KB


def get_command_spec(name: str) -> CommandSpec | None:
    """Look up a command specification by executable name."""
    kb = get_kb()
    return kb.get(name)


def list_known_commands() -> list[str]:
    """Return sorted list of all command names in the knowledge base."""
    return sorted(get_kb())
