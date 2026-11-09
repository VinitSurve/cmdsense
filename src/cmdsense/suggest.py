"""Command suggestion engine for CmdSense.

Translates natural language descriptions of tasks into safe, macOS-compatible shell
commands with explanation, risk level, and safer alternatives.
NEVER executes the generated command.
"""

from __future__ import annotations

from dataclasses import dataclass

from cmdsense.intents import IntentMatch, match_intent
from cmdsense.safety import RiskLevel, SafetyReport, analyze_safety


@dataclass(frozen=True)
class SuggestionReport:
    prompt: str
    suggested_command: str | None
    matched_intent_id: str | None
    title: str | None
    explanation: str
    expected_behavior: str | None
    safer_alternative: str | None
    macos_notes: str | None
    risk_level: RiskLevel
    safety: SafetyReport | None
    is_supported: bool


def suggest_command(prompt: str) -> SuggestionReport:
    """Generate a command suggestion from a natural language prompt."""
    match: IntentMatch | None = match_intent(prompt)
    if not match:
        return SuggestionReport(
            prompt=prompt,
            suggested_command=None,
            matched_intent_id=None,
            title=None,
            explanation=(
                "No matching rule-based intent found for your request. "
                "Try phrasing as an action (e.g., 'Find all files larger than 100MB in Downloads', "
                "'kill process on port 3000', 'undo last git commit', 'check disk space')."
            ),
            expected_behavior=None,
            safer_alternative=None,
            macos_notes=None,
            risk_level=RiskLevel.INFORMATIONAL,
            safety=None,
            is_supported=False,
        )

    # Analyze safety of the suggested command
    safety = analyze_safety(match.command)

    return SuggestionReport(
        prompt=prompt,
        suggested_command=match.command,
        matched_intent_id=match.intent_id,
        title=match.title,
        explanation=match.explanation,
        expected_behavior=match.expected_behavior,
        safer_alternative=match.safer_alternative,
        macos_notes=match.macos_notes,
        risk_level=safety.overall_risk,
        safety=safety,
        is_supported=True,
    )
