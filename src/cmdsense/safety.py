"""Static command safety analyzer and risk classifier for CmdSense.

Classifies commands into five risk levels:
- informational: purely informational / read-only query
- low: minor or standard read-only operations
- moderate: non-destructive mutations or service state changes
- high: potential file modification, privilege escalation, or exposed credentials
- destructive: irreversible deletion, disk wiping, or remote script piping

DISCLAIMER: Static analysis is heuristic and pattern-based. It cannot guarantee
that a command is safe, nor can it catch all obfuscated or dynamic hazards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from cmdsense.parser import CommandLine, Segment, parse_command_line

DISCLAIMER_TEXT = (
    "Disclaimer: Static safety analysis is heuristic and pattern-based. It cannot "
    "guarantee that an unflagged command is completely safe or free of side effects."
)


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    DESTRUCTIVE = "destructive"

    @property
    def score(self) -> int:
        return {
            RiskLevel.INFORMATIONAL: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MODERATE: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.DESTRUCTIVE: 4,
        }[self]

    @property
    def exit_code(self) -> int:
        """Exit code mapping for 'cmdsense safety':
        0 for informational / low / moderate;
        1 for high (warning);
        2 for destructive (error).
        """
        if self in (RiskLevel.INFORMATIONAL, RiskLevel.LOW, RiskLevel.MODERATE):
            return 0
        if self == RiskLevel.HIGH:
            return 1
        return 2


@dataclass(frozen=True)
class SafetyFinding:
    rule_id: str
    risk: RiskLevel
    title: str
    explanation: str
    safer_alternative: str | None = None


@dataclass(frozen=True)
class SafetyReport:
    raw_command: str
    overall_risk: RiskLevel
    findings: list[SafetyFinding]
    disclaimer: str = DISCLAIMER_TEXT

    @property
    def is_safe(self) -> bool:
        return self.overall_risk in (RiskLevel.INFORMATIONAL, RiskLevel.LOW)


# Patterns that indicate high risk or catastrophic destruction
_CAT_TARGETS = re.compile(
    r"^(/|~|/\*|~\*|\$HOME|\$HOME/\*|\.\.|\.\./\*|/System|/System/\*|/usr|/usr/\*|/Library|/Library/\*)$"
)
_CREDENTIAL_KEYWORDS = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|passphrase|private[_-]?key|bearer\s+[A-Za-z0-9_\-\.]{10,})",
    re.IGNORECASE,
)


def analyze_safety(raw_command: str) -> SafetyReport:
    """Analyze the safety of a command string and return a comprehensive report."""
    parsed: CommandLine = parse_command_line(raw_command)
    findings: list[SafetyFinding] = []

    # 1. Pipeline-wide analysis (e.g. curl ... | sh)
    _check_remote_script_pipe(parsed, findings)

    # 2. Per-segment analysis
    for seg in parsed.segments:
        _check_segment(seg, findings)

    # 3. Whole-command regex guards
    _check_whole_command_hazards(raw_command, findings)

    # Compute overall risk level
    if not findings:
        overall = RiskLevel.INFORMATIONAL if _is_pure_informational(parsed) else RiskLevel.LOW
    else:
        max_score = max(f.risk.score for f in findings)
        overall = next(lvl for lvl in RiskLevel if lvl.score == max_score)

    return SafetyReport(
        raw_command=raw_command,
        overall_risk=overall,
        findings=findings,
    )


def _is_pure_informational(parsed: CommandLine) -> bool:
    info_cmds = frozenset(
        {"ls", "pwd", "cat", "head", "tail", "echo", "printf", "which", "type", "man", "date"}
    )
    return all(seg.effective_command in info_cmds for seg in parsed.segments)


def _check_remote_script_pipe(parsed: CommandLine, findings: list[SafetyFinding]) -> None:
    """Detect remote downloaders piped directly into shell interpreters."""
    segments = parsed.segments
    downloaders = frozenset({"curl", "wget", "fetch"})
    shells = frozenset({"sh", "bash", "zsh", "python", "python3", "node", "ruby", "perl"})

    for i in range(len(segments) - 1):
        left = segments[i]
        right = segments[i + 1]
        if (
            left.operator in ("|", "|&")
            and left.effective_command in downloaders
            and right.effective_command in shells
        ):
            findings.append(
                SafetyFinding(
                    rule_id="PIPE_REMOTE_TO_SHELL",
                    risk=RiskLevel.DESTRUCTIVE,
                    title="Remote script piped directly to shell",
                    explanation=(
                        f"Piping downloaded content from '{left.effective_command}' directly into '{right.effective_command}' "
                        "executes remote arbitrary code without inspection, bypassing verification."
                    ),
                    safer_alternative="Download the script to a file first, inspect its source code, and run it explicitly.",
                )
            )


def _check_segment(seg: Segment, findings: list[SafetyFinding]) -> None:
    cmd = seg.effective_command
    args = seg.arguments

    # Recursive / Catastrophic deletion
    if cmd == "rm":
        has_r = any(
            a in ("-r", "-R", "-rf", "-fr") or (a.startswith("-") and ("r" in a or "R" in a))
            for a in args
        )
        has_f = any("f" in a for a in args if a.startswith("-"))
        targets = [a for a in args if not a.startswith("-")]

        is_catastrophic = any(_CAT_TARGETS.match(t.strip()) for t in targets)
        if has_r and is_catastrophic:
            findings.append(
                SafetyFinding(
                    rule_id="RM_RF_CATASTROPHIC",
                    risk=RiskLevel.DESTRUCTIVE,
                    title="Catastrophic recursive deletion",
                    explanation=f"Command attempts to delete vital root, home, or system path recursively ({', '.join(targets)}).",
                    safer_alternative="Target specific subdirectories and use a dry-run or trash utility instead.",
                )
            )
        elif has_r and has_f:
            findings.append(
                SafetyFinding(
                    rule_id="RM_RF_RECURSIVE",
                    risk=RiskLevel.HIGH,
                    title="Forced recursive deletion",
                    explanation="Deletes directory trees permanently and suppresses confirmation prompts.",
                    safer_alternative="Use rm -r -i to prompt before deleting, or inspect the directory beforehand.",
                )
            )
        elif has_r:
            findings.append(
                SafetyFinding(
                    rule_id="RM_RECURSIVE",
                    risk=RiskLevel.MODERATE,
                    title="Recursive deletion",
                    explanation="Recursively deletes files in directory hierarchies.",
                    safer_alternative="Inspect files first with ls or find.",
                )
            )

    # find -delete
    if cmd == "find" and "-delete" in args:
        findings.append(
            SafetyFinding(
                rule_id="FIND_DELETE",
                risk=RiskLevel.HIGH,
                title="Automated deletion via find -delete",
                explanation="find -delete permanently unlinks every file matched by the predicate.",
                safer_alternative="Test the exact find predicate with -print first before appending -delete.",
            )
        )

    # Privilege escalation (sudo / doas)
    if seg.is_sudo:
        findings.append(
            SafetyFinding(
                rule_id="PRIVILEGE_ESCALATION",
                risk=RiskLevel.HIGH,
                title="Superuser privilege escalation (sudo)",
                explanation=f"Command '{cmd}' is executed with root privileges, bypassing standard user permissions.",
                safer_alternative="Execute commands with standard user permissions whenever possible.",
            )
        )

    # Disk formatting / partitioning
    if cmd == "diskutil" and any(a in ("eraseDisk", "eraseVolume", "partitionDisk") for a in args):
        findings.append(
            SafetyFinding(
                rule_id="DISK_FORMATTING",
                risk=RiskLevel.DESTRUCTIVE,
                title="Disk erasure or partitioning",
                explanation="diskutil erase/partition completely wipes target volume or storage drive.",
                safer_alternative="Verify disk identifier with 'diskutil list' before running destructive commands.",
            )
        )

    # Destructive git commands
    if cmd == "git":
        if "reset" in args and "--hard" in args:
            findings.append(
                SafetyFinding(
                    rule_id="GIT_RESET_HARD",
                    risk=RiskLevel.HIGH,
                    title="Destructive git reset --hard",
                    explanation="Discards all uncommitted changes in the working tree and index.",
                    safer_alternative="Use 'git stash' or 'git reset --soft' to preserve uncommitted work.",
                )
            )
        if "clean" in args and any("-f" in a for a in args):
            findings.append(
                SafetyFinding(
                    rule_id="GIT_CLEAN_FORCE",
                    risk=RiskLevel.HIGH,
                    title="Forced removal of untracked files",
                    explanation="git clean -f permanently deletes untracked files without placing them in trash.",
                    safer_alternative="Run 'git clean -n' first to dry-run what would be deleted.",
                )
            )
        if "push" in args and any(a in ("--force", "-f", "--force-with-lease") for a in args):
            findings.append(
                SafetyFinding(
                    rule_id="GIT_PUSH_FORCE",
                    risk=RiskLevel.HIGH,
                    title="Force push to remote git repository",
                    explanation="Force pushing can overwrite and destroy commits in the remote repository branch.",
                    safer_alternative="Use standard git push after merging or rebasing.",
                )
            )

    # Permissive permissions (chmod 777 or -R)
    if cmd == "chmod":
        if "-R" in args:
            findings.append(
                SafetyFinding(
                    rule_id="CHMOD_RECURSIVE",
                    risk=RiskLevel.MODERATE,
                    title="Recursive permission change",
                    explanation="Recursively alters permissions on directory hierarchy.",
                    safer_alternative="Change permissions on specific files only.",
                )
            )
        if any(a in ("777", "a+rwx", "+rwx") for a in args):
            findings.append(
                SafetyFinding(
                    rule_id="CHMOD_WORLD_WRITABLE",
                    risk=RiskLevel.HIGH,
                    title="World-writable file permissions (777)",
                    explanation="Grants unrestricted read, write, and execute permissions to all users on the system.",
                    safer_alternative="Use restrictive permissions such as 755 for directories and 644 for files.",
                )
            )

    # Redirection to raw disk or device files
    for redir in seg.redirections:
        if redir.target.startswith(("/dev/disk", "/dev/rdisk")):
            findings.append(
                SafetyFinding(
                    rule_id="WRITE_TO_RAW_DISK",
                    risk=RiskLevel.DESTRUCTIVE,
                    title="Direct write to raw storage disk device",
                    explanation=f"Redirecting output to '{redir.target}' can overwrite disk partition tables and filesystems.",
                    safer_alternative="Write to regular files rather than raw device nodes.",
                )
            )

    # Dangerous command substitutions
    for sub in seg.substitutions:
        if any(tool in sub.inner for tool in ("curl", "wget", "nc", "bash", "sh")):
            findings.append(
                SafetyFinding(
                    rule_id="DYNAMIC_COMMAND_SUBSTITUTION",
                    risk=RiskLevel.HIGH,
                    title="Network/shell command substitution",
                    explanation=f"Command substitution '$({sub.inner})' dynamically executes network or shell operations.",
                    safer_alternative="Store and inspect the output before evaluating.",
                )
            )


def _check_whole_command_hazards(raw_command: str, findings: list[SafetyFinding]) -> None:
    # Fork bomb detection
    if re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", raw_command):
        findings.append(
            SafetyFinding(
                rule_id="FORK_BOMB",
                risk=RiskLevel.DESTRUCTIVE,
                title="Shell fork bomb detected",
                explanation="Exhausts system process table and freezes the host machine.",
                safer_alternative="Do not execute fork bombs.",
            )
        )

    # Direct raw disk dd write
    if re.search(r"\bdd\b.*\bof=/dev/(r?disk\d+)", raw_command):
        findings.append(
            SafetyFinding(
                rule_id="DD_RAW_DISK",
                risk=RiskLevel.DESTRUCTIVE,
                title="Low-level block write to raw disk device (dd)",
                explanation="Writing blocks directly to disk device can overwrite master boot records or filesystems.",
                safer_alternative="Carefully verify disk identifiers using 'diskutil list'.",
            )
        )

    # Credential exposure in arguments
    # Ignore if command is merely grep searching for the word or echo "pass"
    if _CREDENTIAL_KEYWORDS.search(raw_command) and re.search(
        r"(?:api[_-]?key|secret|token|password)=\S+", raw_command, re.IGNORECASE
    ):
        findings.append(
            SafetyFinding(
                rule_id="CREDENTIAL_EXPOSURE",
                risk=RiskLevel.HIGH,
                title="Potential credential exposure in command line",
                explanation="Sensitive tokens or passwords passed in command arguments may leak to shell history and ps listings.",
                safer_alternative="Use environment variables or secure credential stores instead of plaintext flags.",
            )
        )
