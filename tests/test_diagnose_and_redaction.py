"""Unit tests for CmdSense error diagnosis and secret redaction."""

from __future__ import annotations

import pytest

from cmdsense.diagnose import diagnose_error_text
from cmdsense.errors_kb import ERROR_SIGNATURES


def test_error_signatures_count() -> None:
    assert len(ERROR_SIGNATURES) >= 50, (
        f"Expected at least 50 error signatures, got {len(ERROR_SIGNATURES)}"
    )


@pytest.mark.parametrize(
    ("error_sample", "expected_sig_id"),
    [
        ("ModuleNotFoundError: No module named 'requests'", "py_module_not_found"),
        ("ImportError: cannot import name 'foo'", "py_import_error"),
        ("SyntaxError: invalid syntax", "py_syntax_error"),
        ("IndentationError: expected an indented block", "py_indentation_error"),
        (
            "FileNotFoundError: [Errno 2] No such file or directory: 'data.json'",
            "py_file_not_found",
        ),
        ("error: externally-managed-environment", "py_pep668_externally_managed"),
        ("Error: Cannot find module 'express'", "node_module_not_found"),
        ("npm ERR! code ERESOLVE", "npm_eresolve"),
        ("Error: listen EADDRINUSE :::8080", "node_eaddrinuse"),
        ("fatal: not a git repository (or any of the parent directories): .git", "git_not_a_repo"),
        ("CONFLICT (content): Merge conflict in src/main.py", "git_merge_conflict"),
        ("fatal: Unable to create '.git/index.lock': File exists", "git_index_lock"),
        ("Permission denied (publickey)", "git_ssh_permission_denied"),
        ("Operation not permitted", "macos_operation_not_permitted"),
        (
            "xcrun: error: invalid active developer path (/Library/Developer/CommandLineTools)",
            "macos_xcrun_invalid_active_developer_path",
        ),
        ("zsh: command not found: mytool", "shell_command_not_found"),
        ("zsh: no matches found: *.xyz", "shell_no_matches_found"),
        (
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            "docker_daemon_not_running",
        ),
    ],
)
def test_diagnose_known_errors(error_sample: str, expected_sig_id: str) -> None:
    rep = diagnose_error_text(error_sample)
    assert rep.found_known_issues
    sig_ids = [issue.signature_id for issue in rep.matched_issues]
    assert expected_sig_id in sig_ids
    assert len(rep.matched_issues[0].fixes) > 0


def test_diagnose_redacts_secrets_in_traceback() -> None:
    error_with_secret = (
        "Traceback (most recent call last):\n"
        "  File 'app.py', line 12, in <module>\n"
        "    connect(api_key='sk-live-supersecrettoken123456789')\n"
        "ModuleNotFoundError: No module named 'requests'\n"
    )
    rep = diagnose_error_text(error_with_secret)
    assert "sk-live-supersecrettoken123456789" not in rep.redacted_error
    assert "***REDACTED***" in rep.redacted_error
