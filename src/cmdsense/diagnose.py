"""Terminal error diagnostic engine for CmdSense.

Matches raw terminal error streams or pasted tracebacks against ≥ 50 known
signatures across Python, Node/npm/yarn, Git, macOS, and system utilities.
Redacts secrets before analyzing or returning output.
NEVER executes any suggested fix.
"""

from __future__ import annotations

from dataclasses import dataclass

from cmdsense.common.safety import redact_text
from cmdsense.errors_kb import ErrorFix, ErrorSignature, match_error


@dataclass(frozen=True)
class DiagnosedIssue:
    signature_id: str
    category: str
    title: str
    likely_cause: str
    confidence: str
    fixes: list[ErrorFix]


@dataclass(frozen=True)
class DiagnosisReport:
    raw_error: str
    redacted_error: str
    matched_issues: list[DiagnosedIssue]
    found_known_issues: bool
    summary: str


def diagnose_error_text(error_text: str) -> DiagnosisReport:
    """Analyze terminal error text and produce a structured diagnostic report."""
    redacted = redact_text(error_text)
    matched_sigs: list[ErrorSignature] = match_error(redacted)

    issues: list[DiagnosedIssue] = []
    for sig in matched_sigs:
        issues.append(
            DiagnosedIssue(
                signature_id=sig.signature_id,
                category=sig.category,
                title=sig.title,
                likely_cause=sig.likely_cause,
                confidence=sig.confidence,
                fixes=sig.fixes,
            )
        )

    if issues:
        summary = f"Identified {len(issues)} known issue{'s' if len(issues) != 1 else ''} in terminal output."
    else:
        summary = "No specific known error signature matched. Inspect the redacted traceback above."

    return DiagnosisReport(
        raw_error=error_text,
        redacted_error=redacted,
        matched_issues=issues,
        found_known_issues=len(issues) > 0,
        summary=summary,
    )
