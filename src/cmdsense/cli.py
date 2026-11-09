"""Command line interface for cmdsense."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer

from cmdsense.ai import is_loopback, query_ai
from cmdsense.common.cli import add_config_commands, create_app, exit_with, get_ctx, run_app
from cmdsense.common.config import ConfigStore
from cmdsense.common.exceptions import NotFoundError, UsageError
from cmdsense.common.output import Output
from cmdsense.common.terminal import is_interactive
from cmdsense.config import SCHEMA
from cmdsense.diagnose import diagnose_error_text
from cmdsense.explain import explain_command
from cmdsense.interactive import run_interactive_mode
from cmdsense.render import (
    render_ai_response,
    render_diagnosis,
    render_explanation,
    render_safety_report,
    render_suggestion,
)
from cmdsense.safety import analyze_safety
from cmdsense.suggest import suggest_command

TOOL = "cmdsense"


def _default_action(ctx: typer.Context) -> None:
    tctx = get_ctx(ctx)
    if is_interactive():
        run_interactive_mode(tctx.out)
    else:
        sys.stdout.write(ctx.get_help() + "\n")


app = create_app(
    TOOL,
    "Terminal command intelligence: explain, build, diagnose and safety-check commands.",
    default=_default_action,
)
add_config_commands(app, TOOL, SCHEMA)


@app.command("explain")
def explain(
    ctx: typer.Context,
    command: Annotated[str, typer.Argument(help="Shell command string to explain.")],
    ai: Annotated[
        bool, typer.Option("--ai", help="Query optional AI provider for detailed explanation.")
    ] = False,
) -> None:
    """Explain what a shell command does, flag by flag, with macOS compatibility notes."""
    tctx = get_ctx(ctx)
    expl = explain_command(command)

    if ai:
        store = ConfigStore(tctx.paths, SCHEMA)
        cfg = store.load()
        ai_resp = query_ai(f"Explain this shell command in detail:\n{command}", config=cfg)

        def _render_expl(o: Output) -> None:
            render_explanation(o, expl)
            render_ai_response(o, ai_resp)

        tctx.out.emit({"local": expl, "ai": ai_resp}, _render_expl)
    else:
        tctx.out.emit(expl, lambda o: render_explanation(o, expl))


@app.command("suggest")
def suggest(
    ctx: typer.Context,
    query: Annotated[
        str, typer.Argument(help="Natural language description of what you want to do.")
    ],
    ai: Annotated[
        bool, typer.Option("--ai", help="Query optional AI provider for command suggestion.")
    ] = False,
) -> None:
    """Suggest a safe macOS shell command from a natural language request."""
    tctx = get_ctx(ctx)
    sug = suggest_command(query)

    if ai:
        store = ConfigStore(tctx.paths, SCHEMA)
        cfg = store.load()
        ai_resp = query_ai(
            f"Suggest a safe macOS/POSIX shell command for this task:\n{query}",
            config=cfg,
        )

        def _render_sug(o: Output) -> None:
            render_suggestion(o, sug)
            render_ai_response(o, ai_resp)

        tctx.out.emit({"local": sug, "ai": ai_resp}, _render_sug)
    else:
        tctx.out.emit(sug, lambda o: render_suggestion(o, sug))


@app.command("diagnose")
def diagnose(
    ctx: typer.Context,
    text: Annotated[
        str | None, typer.Option("--text", "-t", help="Raw terminal error text.")
    ] = None,
    file: Annotated[
        Path | None, typer.Option("--file", "-f", help="File containing error output.")
    ] = None,
    ai: Annotated[
        bool, typer.Option("--ai", help="Query optional AI provider for error diagnosis.")
    ] = False,
) -> None:
    """Diagnose terminal error messages or tracebacks and suggest actionable fixes."""
    tctx = get_ctx(ctx)

    raw_input = ""
    if text:
        raw_input = text
    elif file:
        if not file.exists():
            raise NotFoundError(f"Error file not found: {file}")
        raw_input = file.read_text(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read()
    else:
        tctx.out.text("Paste error output (press Ctrl-D on an empty line when finished):")
        try:
            raw_input = sys.stdin.read()
        except (EOFError, KeyboardInterrupt):
            raw_input = ""

    if not raw_input.strip():
        raise UsageError(
            "No error text provided to diagnose.",
            hint="Pipe error output (cmd 2>&1 | cmdsense diagnose) or use --text / --file.",
        )

    diag = diagnose_error_text(raw_input)

    if ai:
        store = ConfigStore(tctx.paths, SCHEMA)
        cfg = store.load()
        ai_resp = query_ai(
            f"Diagnose this terminal error and explain how to fix it:\n{raw_input}",
            config=cfg,
        )

        def _render_diag(o: Output) -> None:
            render_diagnosis(o, diag)
            render_ai_response(o, ai_resp)

        tctx.out.emit({"local": diag, "ai": ai_resp}, _render_diag)
    else:
        tctx.out.emit(diag, lambda o: render_diagnosis(o, diag))


@app.command("safety")
def safety(
    ctx: typer.Context,
    command: Annotated[str, typer.Argument(help="Shell command string to safety check.")],
) -> None:
    """Analyze static safety and security risks of a shell command."""
    tctx = get_ctx(ctx)
    report = analyze_safety(command)
    tctx.out.emit(report, lambda o: render_safety_report(o, report))

    # Exit code reflects the risk level (0 for info/low/mod, 1 for high, 2 for destructive)
    exit_with(report.overall_risk.exit_code)


@app.command("interactive")
def interactive(ctx: typer.Context) -> None:
    """Run interactive terminal assistant."""
    tctx = get_ctx(ctx)
    run_interactive_mode(tctx.out)


ai_app = typer.Typer(
    help="Manage optional AI backend integration.",
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@ai_app.command("status")
def ai_status(ctx: typer.Context) -> None:
    """Show AI configuration and transmission status without making network calls."""
    tctx = get_ctx(ctx)
    store = ConfigStore(tctx.paths, SCHEMA)
    cfg = store.load()

    endpoint = cfg.get("ai_endpoint", "")
    loopback = is_loopback(endpoint)
    data = {
        "enabled": cfg.get("ai_enabled", False),
        "provider": cfg.get("ai_provider", "none"),
        "endpoint": endpoint,
        "is_loopback": loopback,
        "send_confirmed": cfg.get("ai_send_confirmed", False),
        "model": cfg.get("ai_model", ""),
        "api_key_env": cfg.get("ai_api_key_env", ""),
    }

    def render(out: Output) -> None:
        out.heading("CmdSense AI Configuration Status")
        out.kv(
            [
                ("AI Enabled", "Yes" if data["enabled"] else "No (default)"),
                ("Provider", str(data["provider"])),
                ("Endpoint", str(data["endpoint"])),
                ("Loopback (Local)", "Yes" if loopback else "No (Remote Endpoint)"),
                ("Send Confirmed", "Yes" if data["send_confirmed"] else "No"),
                ("Model", str(data["model"])),
            ]
        )
        if not loopback and not data["send_confirmed"]:
            out.warn(
                "Remote AI endpoint configured but 'ai_send_confirmed' is false. "
                "Requests to remote hosts are blocked until confirmed."
            )

    tctx.out.emit(data, render)


@ai_app.command("test")
def ai_test(ctx: typer.Context) -> None:
    """Perform a one-shot probe test against the configured AI endpoint."""
    tctx = get_ctx(ctx)
    store = ConfigStore(tctx.paths, SCHEMA)
    cfg = store.load()

    res = query_ai("Say 'CmdSense AI connection OK'", config=cfg)
    tctx.out.emit(res, lambda o: o.success(f"AI Connection OK: {res.content.strip()}"))


app.add_typer(ai_app, name="ai")


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point; returns the process exit code."""
    return run_app(app, tool=TOOL, argv=argv)
