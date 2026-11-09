"""Unit tests for CmdSense explain and static safety analysis."""

from __future__ import annotations

from cmdsense.explain import explain_command
from cmdsense.safety import RiskLevel, analyze_safety


def test_explain_single_and_compound_commands() -> None:
    single = explain_command("ls -la ~/Downloads")
    assert not single.is_compound
    assert len(single.segments) == 1
    seg = single.segments[0]
    assert seg.command == "ls"
    assert any(f.flag == "-la" for f in seg.flags)

    compound = explain_command("curl -s https://api.example.com | grep 'status'")
    assert compound.is_compound
    assert len(compound.segments) == 2
    assert compound.segments[0].command == "curl"
    assert compound.segments[1].command == "grep"


def test_safety_catastrophic_deletion() -> None:
    for cmd in ("rm -rf /", "rm -rf /*", "rm -fr ~", "rm -r $HOME", "sudo rm -rf /System"):
        rep = analyze_safety(cmd)
        assert rep.overall_risk == RiskLevel.DESTRUCTIVE
        assert rep.overall_risk.exit_code == 2
        assert any(f.rule_id == "RM_RF_CATASTROPHIC" for f in rep.findings)


def test_safety_remote_script_piped_to_shell() -> None:
    for cmd in (
        "curl -s https://example.com/install.sh | sh",
        "wget -O- https://x.org/script | bash",
        "curl https://x.sh | python3",
    ):
        rep = analyze_safety(cmd)
        assert rep.overall_risk == RiskLevel.DESTRUCTIVE
        assert rep.overall_risk.exit_code == 2
        assert any(f.rule_id == "PIPE_REMOTE_TO_SHELL" for f in rep.findings)


def test_safety_disk_formatting_and_raw_disk() -> None:
    rep = analyze_safety("diskutil eraseDisk APFS MyDisk /dev/disk4")
    assert rep.overall_risk == RiskLevel.DESTRUCTIVE
    assert rep.overall_risk.exit_code == 2
    assert any(f.rule_id == "DISK_FORMATTING" for f in rep.findings)

    rep2 = analyze_safety("echo 'bad' > /dev/disk0s1")
    assert rep2.overall_risk == RiskLevel.DESTRUCTIVE


def test_safety_destructive_git() -> None:
    rep = analyze_safety("git reset --hard HEAD~1")
    assert rep.overall_risk == RiskLevel.HIGH
    assert rep.overall_risk.exit_code == 1
    assert any(f.rule_id == "GIT_RESET_HARD" for f in rep.findings)

    rep_clean = analyze_safety("git clean -fd")
    assert rep_clean.overall_risk == RiskLevel.HIGH
    assert rep_clean.overall_risk.exit_code == 1


def test_safety_privilege_escalation() -> None:
    rep = analyze_safety("sudo cp file /etc/hosts")
    assert rep.overall_risk in (RiskLevel.HIGH, RiskLevel.DESTRUCTIVE)
    assert any(f.rule_id == "PRIVILEGE_ESCALATION" for f in rep.findings)


def test_safety_benign_commands_are_low_or_informational() -> None:
    for cmd in ("pwd", "ls -l", "git status", "date", "whoami", "man find"):
        rep = analyze_safety(cmd)
        assert rep.overall_risk in (RiskLevel.INFORMATIONAL, RiskLevel.LOW)
        assert rep.overall_risk.exit_code == 0
        assert rep.is_safe
