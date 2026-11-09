"""Unit tests for CmdSense parser and command knowledge base."""

from __future__ import annotations

from cmdsense.knowledge import get_command_spec, get_kb, list_known_commands
from cmdsense.parser import parse_command_line


def test_knowledge_base_size_and_specs() -> None:
    kb = get_kb()
    assert len(kb) >= 60, f"Expected at least 60 commands in KB, got {len(kb)}"
    names = list_known_commands()
    assert len(names) == len(kb)

    # Core required commands present
    for cmd in (
        "ls",
        "cd",
        "pwd",
        "cat",
        "head",
        "tail",
        "less",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "grep",
        "sed",
        "awk",
        "sort",
        "uniq",
        "wc",
        "xargs",
        "ps",
        "kill",
        "lsof",
        "curl",
        "ssh",
        "rsync",
        "tar",
        "zip",
        "git",
        "npm",
        "pip",
        "python3",
        "node",
        "brew",
        "docker",
        "make",
        "open",
        "pbcopy",
        "pbpaste",
        "defaults",
        "diskutil",
        "sudo",
    ):
        spec = get_command_spec(cmd)
        assert spec is not None, f"Missing command spec for: {cmd}"
        assert spec.summary and spec.expected_output and spec.security


def test_parse_single_command_with_flags_and_arguments() -> None:
    cmd_line = parse_command_line("ls -la /tmp")
    assert len(cmd_line.segments) == 1
    seg = cmd_line.segments[0]
    assert seg.command == "ls"
    assert seg.effective_command == "ls"
    assert seg.arguments == ["-la", "/tmp"]
    assert seg.wrapper_name is None
    assert not seg.is_sudo


def test_parse_sudo_and_env_wrappers() -> None:
    cmd_line = parse_command_line("sudo -u admin env FOO=bar python3 script.py --arg 1")
    assert len(cmd_line.segments) == 1
    seg = cmd_line.segments[0]
    assert seg.is_sudo
    assert seg.wrapper_name in ("sudo", "env")
    assert seg.effective_command == "python3"
    assert seg.arguments == ["script.py", "--arg", "1"]


def test_parse_compound_pipeline_and_operators() -> None:
    cmd_line = parse_command_line("find . -name '*.py' | xargs wc -l && echo 'done'")
    assert len(cmd_line.segments) == 3
    assert cmd_line.segments[0].effective_command == "find"
    assert cmd_line.segments[0].operator == "|"
    assert cmd_line.segments[1].effective_command == "wc"
    assert cmd_line.segments[1].wrapper_name == "xargs"
    assert cmd_line.segments[1].operator == "&&"
    assert cmd_line.segments[2].effective_command == "echo"
    assert cmd_line.segments[2].operator is None


def test_parse_redirections_and_substitutions() -> None:
    cmd_line = parse_command_line("cat < input.txt > output.log 2>&1")
    assert len(cmd_line.segments) == 1
    seg = cmd_line.segments[0]
    symbols = [r.symbol for r in seg.redirections]
    assert "<" in symbols
    assert ">" in symbols or "2>&1" in str(seg.redirections)

    sub_cmd = parse_command_line("echo $(date) `whoami`")
    assert len(sub_cmd.segments[0].substitutions) >= 1
