"""Interactive guided terminal interface for CmdSense."""

from __future__ import annotations

import sys

from cmdsense.common.output import Output
from cmdsense.diagnose import diagnose_error_text
from cmdsense.explain import explain_command
from cmdsense.render import (
    render_diagnosis,
    render_explanation,
    render_safety_report,
    render_suggestion,
)
from cmdsense.safety import analyze_safety
from cmdsense.suggest import suggest_command


def run_interactive_mode(out: Output) -> None:
    """Run interactive terminal interface loop."""
    out.banner("Terminal Command Intelligence — Interactive Mode")

    while True:
        out.text()
        out.heading("Choose an action:")
        out.text("  1) Explain a shell command")
        out.text("  2) Suggest a command from natural language")
        out.text("  3) Diagnose a terminal error")
        out.text("  4) Analyze command safety & risks")
        out.text("  5) Exit")
        out.text()

        try:
            choice = input("Enter choice [1-5]: ").strip()
        except (EOFError, KeyboardInterrupt):
            out.text("\nExiting CmdSense.")
            break

        if choice in ("5", "q", "quit", "exit"):
            out.text("Goodbye!")
            break
        elif choice == "1":
            try:
                cmd = input("Enter command to explain: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if cmd:
                expl = explain_command(cmd)
                render_explanation(out, expl)
        elif choice == "2":
            try:
                prompt = input("Describe what you want to do: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if prompt:
                sug = suggest_command(prompt)
                render_suggestion(out, sug)
        elif choice == "3":
            out.text("Paste error text (press Ctrl-D on empty line when finished):")
            try:
                lines = sys.stdin.read()
            except (EOFError, KeyboardInterrupt):
                lines = ""
            if lines.strip():
                diag = diagnose_error_text(lines)
                render_diagnosis(out, diag)
        elif choice == "4":
            try:
                cmd = input("Enter command to safety check: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if cmd:
                report = analyze_safety(cmd)
                render_safety_report(out, report)
        else:
            out.warn("Invalid choice. Please enter a number between 1 and 5.")
