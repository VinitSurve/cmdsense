"""Command explanation engine for CmdSense.

Parses arbitrary compound shell commands and provides segment-by-segment,
flag-by-flag explanations, macOS compatibility details, and safety analysis.
"""

from __future__ import annotations

from dataclasses import dataclass

from cmdsense.knowledge import CommandSpec, get_command_spec
from cmdsense.parser import CommandLine, Segment, parse_command_line
from cmdsense.safety import SafetyReport, analyze_safety


@dataclass(frozen=True)
class FlagExplanation:
    flag: str
    description: str
    known: bool = True


@dataclass(frozen=True)
class SegmentExplanation:
    raw_segment: str
    command: str
    summary: str
    category: str
    wrapper: str | None
    flags: list[FlagExplanation]
    arguments: list[str]
    redirections: list[str]
    substitutions: list[str]
    operator: str | None
    operator_description: str | None
    expected_output: str
    side_effects: str
    security: str
    macos_notes: str


@dataclass(frozen=True)
class CommandExplanation:
    raw_command: str
    pipeline_summary: str
    segments: list[SegmentExplanation]
    safety: SafetyReport
    is_compound: bool


def explain_command(raw_command: str) -> CommandExplanation:
    """Analyze and explain a command string completely."""
    parsed: CommandLine = parse_command_line(raw_command)
    safety: SafetyReport = analyze_safety(raw_command)

    segment_explanations: list[SegmentExplanation] = []
    for seg in parsed.segments:
        segment_explanations.append(_explain_segment(seg))

    if len(parsed.segments) == 1:
        pipe_summary = f"Single command execution: {parsed.segments[0].effective_command}"
    else:
        cmds = " -> ".join(s.effective_command for s in parsed.segments)
        pipe_summary = f"Compound shell pipeline / chain: {cmds}"

    return CommandExplanation(
        raw_command=raw_command,
        pipeline_summary=pipe_summary,
        segments=segment_explanations,
        safety=safety,
        is_compound=len(parsed.segments) > 1,
    )


def _explain_segment(seg: Segment) -> SegmentExplanation:
    cmd_name = seg.effective_command
    spec: CommandSpec | None = get_command_spec(cmd_name)

    # 1. Summary & Category
    if spec:
        summary = spec.summary
        category = spec.category
        expected_output = spec.expected_output
        side_effects = spec.side_effects
        security = spec.security
        macos_notes = spec.macos_notes
    else:
        summary = f"External executable or command: '{cmd_name}'"
        category = "custom_command"
        expected_output = "Output defined by the specific command executable."
        side_effects = "Standard process execution side effects."
        security = "Unknown command; verify binary provenance and options."
        macos_notes = "Standard macOS / POSIX executable behavior."

    # 2. Flag explanations
    flags_list: list[FlagExplanation] = []
    args_list: list[str] = []

    # Check for known subcommands first (e.g. git status, brew install)
    if spec and spec.subcommands and seg.arguments:
        first_arg = seg.arguments[0]
        if first_arg in spec.subcommands:
            flags_list.append(
                FlagExplanation(
                    flag=first_arg,
                    description=spec.subcommands[first_arg],
                    known=True,
                )
            )

    # Parse flags
    for arg in seg.arguments:
        if spec and spec.subcommands and arg == seg.arguments[0] and arg in spec.subcommands:
            continue
        if arg.startswith("-") and len(arg) > 1:
            desc = _lookup_flag_desc(spec, arg)
            if desc:
                flags_list.append(FlagExplanation(flag=arg, description=desc, known=True))
            else:
                flags_list.append(
                    FlagExplanation(
                        flag=arg,
                        description="No built-in knowledge of this specific flag.",
                        known=False,
                    )
                )
        else:
            args_list.append(arg)

    # 3. Redirections and substitutions
    redir_descs = [f"{r.symbol} {r.target}" for r in seg.redirections]
    sub_descs = [f"$({s.inner})" for s in seg.substitutions]

    # 4. Operator description
    op_desc = None
    if seg.operator:
        from cmdsense.parser import OPERATOR_DESCRIPTIONS

        op_desc = OPERATOR_DESCRIPTIONS.get(seg.operator, f"Shell operator '{seg.operator}'")

    return SegmentExplanation(
        raw_segment=seg.raw_text,
        command=cmd_name,
        summary=summary,
        category=category,
        wrapper=seg.wrapper_name,
        flags=flags_list,
        arguments=args_list,
        redirections=redir_descs,
        substitutions=sub_descs,
        operator=seg.operator,
        operator_description=op_desc,
        expected_output=expected_output,
        side_effects=side_effects,
        security=security,
        macos_notes=macos_notes,
    )


def _lookup_flag_desc(spec: CommandSpec | None, flag: str) -> str | None:
    if not spec:
        return None

    # Exact match
    if flag in spec.flags:
        return spec.flags[flag]

    # Bundled single-character flags (e.g. -rf -> -r, -f)
    if flag.startswith("-") and not flag.startswith("--") and len(flag) > 2 and not spec.word_flags:
        descs: list[str] = []
        for char in flag[1:]:
            single = f"-{char}"
            if single in spec.flags:
                descs.append(f"{single}: {spec.flags[single]}")
            else:
                descs.append(f"{single}: (unknown)")
        return "; ".join(descs)

    return None
