"""Rich formatting and rendering helpers for CmdSense."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cmdsense.ai import AIResponse
from cmdsense.common.output import Output
from cmdsense.diagnose import DiagnosisReport
from cmdsense.explain import CommandExplanation
from cmdsense.safety import RiskLevel, SafetyReport
from cmdsense.suggest import SuggestionReport

_RISK_STYLES: dict[RiskLevel, str] = {
    RiskLevel.INFORMATIONAL: "blue",
    RiskLevel.LOW: "green",
    RiskLevel.MODERATE: "yellow",
    RiskLevel.HIGH: "bold magenta",
    RiskLevel.DESTRUCTIVE: "bold red",
}


def render_safety_report(out: Output, report: SafetyReport) -> None:
    style = _RISK_STYLES.get(report.overall_risk, "info")
    title = f"Safety Analysis: {report.overall_risk.value.upper()}"

    body = Table.grid(padding=(0, 2))
    body.add_column(style="key", no_wrap=True)
    body.add_column()
    body.add_row("Command", report.raw_command)
    body.add_row("Risk Level", Text(report.overall_risk.value.upper(), style=style))

    if report.findings:
        findings_table = Table(title="Risk Findings", title_style="heading", border_style="muted")
        findings_table.add_column("Rule ID", style="cyan")
        findings_table.add_column("Risk", style=style)
        findings_table.add_column("Finding", style="default")
        findings_table.add_column("Safer Alternative", style="muted")

        for f in report.findings:
            f_style = _RISK_STYLES.get(f.risk, "info")
            findings_table.add_row(
                f.rule_id,
                Text(f.risk.value, style=f_style),
                f"{f.title}\n{f.explanation}",
                f.safer_alternative or "None",
            )
        out.render(Panel(body, title=title, border_style=style))
        out.render(findings_table)
    else:
        out.render(Panel(body, title=title, border_style=style))
        out.status("ok", "No elevated risk patterns or destructive operators detected.")

    out.muted(report.disclaimer)


def render_explanation(out: Output, expl: CommandExplanation) -> None:
    out.heading("CmdSense Command Explanation")
    out.kv([("Command", expl.raw_command), ("Summary", expl.pipeline_summary)])

    for idx, seg in enumerate(expl.segments, start=1):
        seg_title = f"Segment {idx}: {seg.command}"
        if seg.wrapper:
            seg_title += f" (via {seg.wrapper})"

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="key", no_wrap=True)
        grid.add_column()
        grid.add_row("Executable", seg.command)
        grid.add_row("Category", seg.category)
        grid.add_row("Purpose", seg.summary)
        grid.add_row("Expected Output", seg.expected_output)
        grid.add_row("Side Effects", seg.side_effects)
        grid.add_row("macOS Notes", seg.macos_notes)
        if seg.operator:
            grid.add_row("Operator", f"{seg.operator} — {seg.operator_description}")

        out.render(Panel(grid, title=seg_title, border_style="cyan"))

        if seg.flags:
            flag_table = Table(title=f"Flags & Arguments for '{seg.command}'", border_style="muted")
            flag_table.add_column("Flag / Arg", style="cyan")
            flag_table.add_column("Description", style="default")
            flag_table.add_column("Known", style="muted")
            for f in seg.flags:
                flag_table.add_row(f.flag, f.description, "✓" if f.known else "–")
            out.render(flag_table)

    # Safety footer
    risk_style = _RISK_STYLES.get(expl.safety.overall_risk, "info")
    out.status(
        "warn" if expl.safety.overall_risk in (RiskLevel.HIGH, RiskLevel.DESTRUCTIVE) else "info",
        f"Safety Verdict: [{risk_style}]{expl.safety.overall_risk.value.upper()}[/{risk_style}]",
    )


def render_suggestion(out: Output, sug: SuggestionReport) -> None:
    out.heading("CmdSense Command Suggestion")
    out.kv([("Request", sug.prompt)])

    if not sug.is_supported or not sug.suggested_command:
        out.warn(sug.explanation)
        return

    risk_style = _RISK_STYLES.get(sug.risk_level, "info")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="key", no_wrap=True)
    grid.add_column()
    grid.add_row("Suggested Command", Text(sug.suggested_command, style="bold green"))
    grid.add_row("Explanation", sug.explanation)
    grid.add_row("Risk Level", Text(sug.risk_level.value.upper(), style=risk_style))
    if sug.expected_behavior:
        grid.add_row("Expected Output", sug.expected_behavior)
    if sug.macos_notes:
        grid.add_row("macOS Compatibility", sug.macos_notes)
    if sug.safer_alternative:
        grid.add_row("Safer Alternative", sug.safer_alternative)

    out.render(Panel(grid, title=sug.title or "Suggested Command", border_style="green"))
    out.next_steps(
        [
            "Copy and review the command before executing in your terminal.",
            f'cmdsense safety "{sug.suggested_command}"',
        ]
    )


def render_diagnosis(out: Output, diag: DiagnosisReport) -> None:
    out.heading("CmdSense Error Diagnosis")
    if diag.found_known_issues:
        for idx, issue in enumerate(diag.matched_issues, start=1):
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="key", no_wrap=True)
            grid.add_column()
            grid.add_row("Issue", issue.title)
            grid.add_row("Category", issue.category)
            grid.add_row("Likely Cause", issue.likely_cause)

            out.render(Panel(grid, title=f"Issue {idx}: {issue.title}", border_style="yellow"))

            if issue.fixes:
                fix_table = Table(title="Recommended Fixes", border_style="muted")
                fix_table.add_column("Action", style="cyan")
                fix_table.add_column("Command", style="green")
                fix_table.add_column("Explanation", style="muted")
                for fix in issue.fixes:
                    fix_table.add_row(fix.title, fix.command or "–", fix.explanation)
                out.render(fix_table)
    else:
        out.warn(diag.summary)


def render_ai_response(out: Output, resp: AIResponse) -> None:
    out.heading(f"CmdSense AI Response ({resp.provider} / {resp.model})")
    out.render(Panel(resp.content, title="AI Suggestion", border_style="magenta"))
    out.muted(resp.disclaimer)
