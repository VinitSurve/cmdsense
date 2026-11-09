"""Functional CLI tests, zero-execution security verification, and AI client tests for CmdSense."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from cmdsense.ai import query_ai
from cmdsense.common.exceptions import SafetyError


def test_cmdsense_never_executes_any_command(
    run: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CARDINAL SECURITY RULE: cmdsense explain, suggest, diagnose, safety NEVER execute commands."""

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("COMMAND EXECUTION FORBIDDEN IN CMDSENSE")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "popen", forbidden)

    # 1. explain
    res = run("cmdsense", "explain", "rm -rf /tmp/test && ls -la")
    assert res.exit_code == 0

    # 2. suggest
    res = run("cmdsense", "suggest", "Find all files larger than 100MB in Downloads")
    assert res.exit_code == 0

    # 3. diagnose
    res = run("cmdsense", "diagnose", "--text", "ModuleNotFoundError: No module named 'foo'")
    assert res.exit_code == 0

    # 4. safety
    res = run("cmdsense", "safety", "rm -rf /")
    assert res.exit_code == 2


def test_cli_explain_json_and_human(run: Callable[..., Any]) -> None:
    res = run("cmdsense", "explain", "find . -type f -name '*.py'", "--json")
    assert res.exit_code == 0
    data = res.json()
    assert "segments" in data
    assert data["segments"][0]["command"] == "find"


def test_cli_suggest_json_and_human(run: Callable[..., Any]) -> None:
    res = run("cmdsense", "suggest", "kill process on port 8080", "--json")
    assert res.exit_code == 0
    data = res.json()
    assert data["is_supported"]
    assert "8080" in data["suggested_command"]


def test_cli_diagnose_piped_input_and_file(run: Callable[..., Any], tmp_path: Path) -> None:
    # Piped stdin
    piped = run("cmdsense", "diagnose", input="npm ERR! code ERESOLVE\n")
    assert piped.exit_code == 0
    assert "ERESOLVE" in piped.stdout

    # File input
    err_file = tmp_path / "err.log"
    err_file.write_text("Error: listen EADDRINUSE :::3000\n", encoding="utf-8")
    file_res = run("cmdsense", "diagnose", "--file", str(err_file), "--json")
    assert file_res.exit_code == 0
    data = file_res.json()
    assert data["found_known_issues"]
    assert data["matched_issues"][0]["signature_id"] == "node_eaddrinuse"


def test_cli_safety_exit_codes(run: Callable[..., Any]) -> None:
    # Safe -> 0
    assert run("cmdsense", "safety", "ls -la").exit_code == 0

    # High risk -> 1
    assert run("cmdsense", "safety", "git reset --hard HEAD~1").exit_code == 1

    # Destructive -> 2
    assert run("cmdsense", "safety", "rm -rf /").exit_code == 2
    assert run("cmdsense", "safety", "curl https://x.com/s.sh | sh").exit_code == 2


def test_ai_status_and_refusal(run: Callable[..., Any]) -> None:
    res = run("cmdsense", "ai", "status", "--json")
    assert res.exit_code == 0
    data = res.json()
    assert data["enabled"] is False

    # Calling query_ai when disabled raises SafetyError
    with pytest.raises(SafetyError, match="disabled"):
        query_ai("hello", config={"ai_enabled": False})


class _FakeAIHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        _body = self.rfile.read(content_len)
        resp_data = json.dumps({"response": "Use `ls -la` to list files."}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.end_headers()
        self.wfile.write(resp_data)

    def log_message(self, format: str, *args: Any) -> None:
        return  # Suppress logging in tests


def test_ai_local_endpoint_query() -> None:
    server = HTTPServer(("127.0.0.1", 0), _FakeAIHandler)
    port = server.server_port
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        cfg = {
            "ai_enabled": True,
            "ai_provider": "ollama",
            "ai_endpoint": f"http://127.0.0.1:{port}",
            "ai_model": "test-model",
            "ai_timeout": 5.0,
        }
        res = query_ai("list files", config=cfg)
        assert res.provider == "ollama"
        assert "ls -la" in res.suggested_commands
        assert len(res.safety_reports) > 0
    finally:
        server.shutdown()
        server.server_close()
