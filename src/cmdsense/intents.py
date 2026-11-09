"""Natural language command suggestion templates and intent definitions for CmdSense.

Defines ≥ 40 common developer and macOS task intents with parameter extraction
and strict shlex.quote sanitization to prevent shell injection vulnerabilities.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class IntentMatch:
    intent_id: str
    title: str
    command: str
    explanation: str
    expected_behavior: str
    safer_alternative: str | None
    macos_notes: str


@dataclass
class IntentTemplate:
    intent_id: str
    title: str
    patterns: list[re.Pattern[str]]
    builder: Callable[[re.Match[str], str], IntentMatch | None]


def _safe_path(raw: str, default: str = ".") -> str:
    cleaned = raw.strip().rstrip("/").strip("'\"")
    # Neutralize dangerous shell expansion and operator characters; reject malicious input
    if re.search(r"[`$;|&><()\n]", cleaned):
        return default
    if not cleaned:
        return default
    if cleaned.lower() in ("downloads", "~/downloads"):
        return "~/Downloads"
    if cleaned.lower() in ("desktop", "~/desktop"):
        return "~/Desktop"
    if cleaned.lower() in ("documents", "~/documents"):
        return "~/Documents"
    if cleaned.lower() in ("here", "current folder", "current directory", "pwd"):
        return "."
    return shlex.quote(cleaned)


def _safe_size(raw: str, default: str = "100M") -> str:
    cleaned = raw.strip().upper()
    m = re.search(r"(\d+(?:\.\d+)?)\s*([KMGT]?B?)", cleaned)
    if m:
        num, unit = m.group(1), m.group(2)
        unit_char = unit[0] if unit else "M"
        return f"+{int(float(num))}{unit_char}"
    return f"+{default}"


def _safe_port(raw: str, default: str = "3000") -> str:
    m = re.search(r"\b(\d{2,5})\b", raw)
    if m:
        return m.group(1)
    return default


def _safe_ext(raw: str, default: str = "txt") -> str:
    cleaned = raw.strip().lstrip(".*").lower()
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "", cleaned)
    return cleaned or default


def _safe_token(raw: str, default: str = "example") -> str:
    cleaned = raw.strip().strip("'\"")
    return shlex.quote(cleaned) or shlex.quote(default)


INTENT_TEMPLATES: list[IntentTemplate] = [
    # 1. Find files by size
    IntentTemplate(
        intent_id="find_files_by_size",
        title="Find files by size",
        patterns=[
            re.compile(r"find.*files.*larger than\s+(\d+\s*[a-zA-Z]+)(?:\s+in\s+(.+))?", re.I),
            re.compile(r"search.*files.*bigger than\s+(\d+\s*[a-zA-Z]+)(?:\s+in\s+(.+))?", re.I),
            re.compile(
                r"files\s+(?:greater|more)\s+than\s+(\d+\s*[a-zA-Z]+)(?:\s+in\s+(.+))?", re.I
            ),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="find_files_by_size",
            title="Find files larger than specified size",
            command=f"find {_safe_path(m.group(2) or '.')} -type f -size {_safe_size(m.group(1))} -exec ls -lh {{}} +",
            explanation=f"Searches recursively for regular files larger than {m.group(1).strip()} and displays sizes in human-readable format.",
            expected_behavior="Lists matching files and their file sizes.",
            safer_alternative="Omit '-exec ls' and use '-print' to only list file paths first.",
            macos_notes="Uses macOS BSD find size syntax.",
        ),
    ),
    # 2. Find files by extension
    IntentTemplate(
        intent_id="find_files_by_extension",
        title="Find files by extension",
        patterns=[
            re.compile(r"find.*(?:\*\.)?([a-zA-Z0-9]+)\s+files(?:\s+in\s+(.+))?", re.I),
            re.compile(r"search.*(?:\*\.)?([a-zA-Z0-9]+)\s+files(?:\s+in\s+(.+))?", re.I),
            re.compile(r"list\s+all\s+(?:\*\.)?([a-zA-Z0-9]+)\s+files(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="find_files_by_extension",
            title="Find files with matching extension",
            command=f"find {_safe_path(m.group(2) or '.')} -type f -name '*.{_safe_ext(m.group(1))}'",
            explanation=f"Finds all regular files ending with '.{_safe_ext(m.group(1))}'.",
            expected_behavior="Prints matching file paths, one per line.",
            safer_alternative=None,
            macos_notes="Standard BSD find.",
        ),
    ),
    # 3. Find files modified recently
    IntentTemplate(
        intent_id="find_files_modified_recently",
        title="Find recently modified files",
        patterns=[
            re.compile(
                r"files\s+modified\s+in\s+(?:the\s+)?last\s+(\d+)\s+days?(?:\s+in\s+(.+))?", re.I
            ),
            re.compile(
                r"find.*changed\s+in\s+(?:the\s+)?past\s+(\d+)\s+days?(?:\s+in\s+(.+))?", re.I
            ),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="find_files_modified_recently",
            title="Find files modified in last N days",
            command=f"find {_safe_path(m.group(2) or '.')} -type f -mtime -{m.group(1)}",
            explanation=f"Finds regular files modified within the past {m.group(1)} days.",
            expected_behavior="Prints paths of recently modified files.",
            safer_alternative=None,
            macos_notes="Uses BSD find -mtime.",
        ),
    ),
    # 4. Find empty files or directories
    IntentTemplate(
        intent_id="find_empty_files",
        title="Find empty files or folders",
        patterns=[
            re.compile(
                r"find\s+(?:all\s+)?empty\s+(files|folders|directories)(?:\s+in\s+(.+))?", re.I
            ),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="find_empty_files",
            title="Find empty files or folders",
            command=f"find {_safe_path(m.group(2) or '.')} -type {'f' if 'file' in m.group(1).lower() else 'd'} -empty",
            explanation=f"Searches for 0-byte {m.group(1).lower()}.",
            expected_behavior="Lists empty paths without deleting them.",
            safer_alternative="Always inspect the empty paths before piping to any delete command.",
            macos_notes="macOS BSD find supports -empty.",
        ),
    ),
    # 5. Disk usage summary
    IntentTemplate(
        intent_id="disk_usage_summary",
        title="Check directory disk usage",
        patterns=[
            re.compile(
                r"(?:disk\s+usage|size\s+of|how\s+big\s+is)(?:\s+the\s+folder)?\s+(.+)", re.I
            ),
            re.compile(r"check\s+disk\s+space\s+of\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="disk_usage_summary",
            title="Check directory disk usage summary",
            command=f"du -sh {_safe_path(m.group(1))}",
            explanation=f"Calculates total human-readable size of {m.group(1).strip()}.",
            expected_behavior="Prints total size and directory path.",
            safer_alternative=None,
            macos_notes="Uses macOS BSD du.",
        ),
    ),
    # 6. Largest files in directory
    IntentTemplate(
        intent_id="largest_files",
        title="Find largest files",
        patterns=[
            re.compile(
                r"(?:(?:find|top)\s+)?(?:(\d+)\s+)?(?:largest|biggest)\s+files(?:\s+in\s+(.+))?",
                re.I,
            ),
            re.compile(r"find\s+large\s+files(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="largest_files",
            title="List largest files in directory",
            command=f"find {_safe_path(m.group(2) or '.')} -type f -exec ls -lh {{}} + | sort -k 5 -hr | head -n {m.group(1) or '10'}",
            explanation=f"Locates files and sorts by size descending, showing the top {m.group(1) or '10'}.",
            expected_behavior="Table of top largest files.",
            safer_alternative=None,
            macos_notes="Compatible with BSD ls and sort.",
        ),
    ),
    # 7. Largest directories
    IntentTemplate(
        intent_id="largest_directories",
        title="Find largest subdirectories",
        patterns=[
            re.compile(r"(?:find|largest|biggest)\s+folders(?:\s+in\s+(.+))?", re.I),
            re.compile(r"largest\s+directories(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="largest_directories",
            title="List largest subdirectories",
            command=f"du -sh {_safe_path(m.group(1) or '.')}/* 2>/dev/null | sort -hr | head -n 10",
            explanation="Calculates immediate subdirectory sizes and sorts by size descending.",
            expected_behavior="Top 10 largest folders and sizes.",
            safer_alternative=None,
            macos_notes="Uses macOS du and sort.",
        ),
    ),
    # 8. Delete node_modules
    IntentTemplate(
        intent_id="delete_node_modules",
        title="Delete node_modules folders",
        patterns=[
            re.compile(r"(?:delete|remove|clean)\s+node_modules(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="delete_node_modules",
            title="Safely remove node_modules directories",
            command=f"find {_safe_path(m.group(1) or '.')} -name 'node_modules' -type d -prune -exec rm -rf {{}} +",
            explanation="Recursively finds and deletes node_modules folders.",
            expected_behavior="Permanently deletes node_modules folders to reclaim disk space.",
            safer_alternative=f"Run first: find {_safe_path(m.group(1) or '.')} -name 'node_modules' -type d -prune to preview directories.",
            macos_notes="Uses BSD find -prune.",
        ),
    ),
    # 9. Kill process on port
    IntentTemplate(
        intent_id="kill_process_on_port",
        title="Kill process listening on port",
        patterns=[
            re.compile(r"kill\s+(?:process\s+on\s+)?port\s+(\d+)", re.I),
            re.compile(r"stop\s+(?:server\s+on\s+)?port\s+(\d+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="kill_process_on_port",
            title="Terminate process listening on network port",
            command=f"lsof -ti :{_safe_port(m.group(1))} | xargs kill -9",
            explanation=f"Finds PID listening on port {m.group(1)} and sends SIGKILL.",
            expected_behavior="Terminates the process occupying the port.",
            safer_alternative=f"Inspect first: lsof -i :{_safe_port(m.group(1))} before sending kill signal.",
            macos_notes="Standard macOS diagnostic pattern.",
        ),
    ),
    # 10. Show listening ports
    IntentTemplate(
        intent_id="show_listening_ports",
        title="Show listening ports",
        patterns=[
            re.compile(r"(?:show|list|check)\s+(?:listening|open)\s+ports", re.I),
            re.compile(r"what\s+is\s+listening\s+on\s+ports?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="show_listening_ports",
            title="List all listening network ports",
            command="lsof -iTCP -sTCP:LISTEN -n -P",
            explanation="Lists all processes currently listening on TCP sockets.",
            expected_behavior="Table showing command names, PIDs, and listening port numbers.",
            safer_alternative=None,
            macos_notes="macOS native lsof command.",
        ),
    ),
    # 11. Git undo last commit (soft)
    IntentTemplate(
        intent_id="git_undo_last_commit",
        title="Undo last git commit (preserve changes)",
        patterns=[
            re.compile(r"(?:undo|rollback)\s+(?:last\s+)?git\s+commit", re.I),
            re.compile(r"git\s+undo\s+commit", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="git_undo_last_commit",
            title="Undo last commit and keep changes staged",
            command="git reset --soft HEAD~1",
            explanation="Moves HEAD back by one commit while leaving working tree and staging index intact.",
            expected_behavior="Last commit is removed from git log, but your code remains in staging.",
            safer_alternative="Always prefer 'git reset --soft' over 'git reset --hard' to avoid data loss.",
            macos_notes="Standard git behavior.",
        ),
    ),
    # 12. Git stash changes
    IntentTemplate(
        intent_id="git_stash_changes",
        title="Stash git changes",
        patterns=[
            re.compile(r"git\s+stash(?:\s+changes)?", re.I),
            re.compile(r"save\s+uncommitted\s+changes", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="git_stash_changes",
            title="Stash working directory changes",
            command="git stash push -m 'Saved changes'",
            explanation="Temporarily shelves modified tracked files so you have a clean working tree.",
            expected_behavior="Working tree is clean; changes stored in git stash stack.",
            safer_alternative="Use 'git stash pop' later to restore shelved changes.",
            macos_notes="Standard git.",
        ),
    ),
    # 13. Git delete merged branches
    IntentTemplate(
        intent_id="git_delete_merged_branches",
        title="Delete merged git branches",
        patterns=[
            re.compile(r"delete\s+merged\s+(?:git\s+)?branches", re.I),
            re.compile(r"clean\s+up\s+(?:old\s+)?git\s+branches", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="git_delete_merged_branches",
            title="Delete local branches already merged into main",
            command="git branch --merged | grep -v -E '^(\\*|\\s*(main|master|develop)$)' | xargs git branch -d",
            explanation="Lists merged branches, filters out current and main branches, and safely deletes them.",
            expected_behavior="Deletes local merged branches with git branch -d (refuses unmerged).",
            safer_alternative="Use -d (safe) rather than -D (forced deletion).",
            macos_notes="Compatible with BSD grep and xargs.",
        ),
    ),
    # 14. Git show recent commit log
    IntentTemplate(
        intent_id="git_recent_commits",
        title="Show recent git commit log",
        patterns=[
            re.compile(r"(?:show|view|see)\s+(?:recent\s+)?(?:git\s+)?commits?", re.I),
            re.compile(r"git\s+log\s+oneline", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="git_recent_commits",
            title="Display concise git commit history",
            command="git log --oneline --graph --decorate -n 15",
            explanation="Prints the last 15 commits with branch decorations and ASCII graph.",
            expected_behavior="Compact commit history.",
            safer_alternative=None,
            macos_notes="Standard git.",
        ),
    ),
    # 15. Git discard unstaged changes
    IntentTemplate(
        intent_id="git_discard_unstaged",
        title="Discard unstaged git changes",
        patterns=[
            re.compile(r"(?:discard|revert)\s+(?:all\s+)?unstaged\s+changes", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="git_discard_unstaged",
            title="Restore working tree files to HEAD",
            command="git restore .",
            explanation="Discards all unstaged modifications in current working directory.",
            expected_behavior="Reverts modified tracked files to last committed state.",
            safer_alternative="Run 'git diff' to review changes before discarding.",
            macos_notes="Git 2.23+ restore command.",
        ),
    ),
    # 16. Search text in files
    IntentTemplate(
        intent_id="search_text_in_files",
        title="Search text in files",
        patterns=[
            re.compile(
                r"search\s+(?:for\s+)?[\"']?([^\"']+)[\"']?\s+in\s+files?(?:\s+in\s+(.+))?", re.I
            ),
            re.compile(
                r"find\s+(?:text\s+)?[\"']?([^\"']+)[\"']?\s+in\s+code(?:\s+in\s+(.+))?", re.I
            ),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="search_text_in_files",
            title="Search for text pattern in files recursively",
            command=f"grep -rn {_safe_token(m.group(1))} {_safe_path(m.group(2) or '.')}",
            explanation=f"Recursively searches files for '{m.group(1)}' with line numbers.",
            expected_behavior="Lists matching filenames, line numbers, and matching text.",
            safer_alternative="Use ripgrep ('rg') if installed for faster searching and .gitignore respect.",
            macos_notes="macOS BSD grep.",
        ),
    ),
    # 17. Count lines of code
    IntentTemplate(
        intent_id="count_lines_of_code",
        title="Count lines of code",
        patterns=[
            re.compile(r"count\s+(?:lines\s+of\s+code|loc)(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="count_lines_of_code",
            title="Count lines of code in directory",
            command=f"find {_safe_path(m.group(1) or '.')} -type f ! -path '*/.*' -exec wc -l {{}} + | sort -n",
            explanation="Calculates line counts for non-hidden files and sorts ascending.",
            expected_behavior="Line counts per file and grand total.",
            safer_alternative=None,
            macos_notes="Standard BSD find and wc.",
        ),
    ),
    # 18. Compress into tar.gz
    IntentTemplate(
        intent_id="compress_tar_gz",
        title="Compress folder into tar.gz",
        patterns=[
            re.compile(r"(?:compress|tar|archive)\s+(.+)\s+to\s+([a-zA-Z0-9_\-\.]+)", re.I),
            re.compile(r"create\s+tar\.gz\s+of\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="compress_tar_gz",
            title="Create gzipped tar archive",
            command=f"tar -czvf archive.tar.gz {_safe_path(m.group(1))}",
            explanation=f"Archives and compresses '{m.group(1).strip()}' into archive.tar.gz.",
            expected_behavior="Creates archive.tar.gz file.",
            safer_alternative=None,
            macos_notes="macOS BSD tar supports gzip compression natively.",
        ),
    ),
    # 19. Extract tar.gz
    IntentTemplate(
        intent_id="extract_tar_gz",
        title="Extract tar.gz archive",
        patterns=[
            re.compile(r"(?:extract|untar|uncompress)\s+(.+\.tar\.gz)", re.I),
            re.compile(r"(?:extract|untar)\s+(.+\.tgz)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="extract_tar_gz",
            title="Extract compressed tarball",
            command=f"tar -xzvf {_safe_path(m.group(1))}",
            explanation=f"Extracts files from '{m.group(1).strip()}' into current working directory.",
            expected_behavior="Decompresses archive and writes files to disk.",
            safer_alternative=f"List contents first: tar -ztvf {_safe_path(m.group(1))}.",
            macos_notes="macOS BSD tar.",
        ),
    ),
    # 20. Compress into zip
    IntentTemplate(
        intent_id="compress_zip",
        title="Compress folder into zip",
        patterns=[
            re.compile(r"zip\s+(?:up\s+)?folder\s+(.+)", re.I),
            re.compile(r"create\s+zip\s+of\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="compress_zip",
            title="Create zip archive recursively",
            command=f"zip -r archive.zip {_safe_path(m.group(1))}",
            explanation=f"Compresses directory '{m.group(1).strip()}' into archive.zip.",
            expected_behavior="Creates archive.zip file.",
            safer_alternative=None,
            macos_notes="Uses macOS /usr/bin/zip.",
        ),
    ),
    # 21. Extract zip
    IntentTemplate(
        intent_id="extract_zip",
        title="Extract zip archive",
        patterns=[
            re.compile(r"unzip\s+(.+\.zip)", re.I),
            re.compile(r"extract\s+(.+\.zip)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="extract_zip",
            title="Extract zip archive",
            command=f"unzip {_safe_path(m.group(1))}",
            explanation=f"Extracts files from '{m.group(1).strip()}'.",
            expected_behavior="Extracts contents into current directory.",
            safer_alternative=f"List contents first: unzip -l {_safe_path(m.group(1))}.",
            macos_notes="Uses macOS /usr/bin/unzip.",
        ),
    ),
    # 22. Copy directory recursively
    IntentTemplate(
        intent_id="copy_directory",
        title="Copy directory recursively",
        patterns=[
            re.compile(r"copy\s+(?:folder|directory)\s+(.+)\s+to\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="copy_directory",
            title="Copy directory structure and contents",
            command=f"cp -R {_safe_path(m.group(1))} {_safe_path(m.group(2))}",
            explanation=f"Recursively copies '{m.group(1).strip()}' to '{m.group(2).strip()}'.",
            expected_behavior="Creates copy of directory at destination.",
            safer_alternative="Use cp -R -n to prevent overwriting existing files.",
            macos_notes="macOS BSD cp supports APFS clone copy with -c.",
        ),
    ),
    # 23. Move / rename directory
    IntentTemplate(
        intent_id="move_directory",
        title="Move or rename folder",
        patterns=[
            re.compile(r"(?:move|rename)\s+(?:folder|directory)\s+(.+)\s+to\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="move_directory",
            title="Move or rename directory",
            command=f"mv {_safe_path(m.group(1))} {_safe_path(m.group(2))}",
            explanation=f"Moves or renames '{m.group(1).strip()}' to '{m.group(2).strip()}'.",
            expected_behavior="Relocates directory.",
            safer_alternative="Use mv -n to prevent accidental replacement.",
            macos_notes="Atomic on macOS APFS filesystems.",
        ),
    ),
    # 24. Download file with curl
    IntentTemplate(
        intent_id="download_curl",
        title="Download file with curl",
        patterns=[
            re.compile(r"download\s+(https?://\S+)", re.I),
            re.compile(r"curl\s+download\s+(https?://\S+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="download_curl",
            title="Download remote file to local disk",
            command=f"curl -O -L {shlex.quote(m.group(1))}",
            explanation=f"Downloads file from '{m.group(1)}' following redirects.",
            expected_behavior="Saves downloaded content to disk.",
            safer_alternative=None,
            macos_notes="Native macOS curl.",
        ),
    ),
    # 25. Show environment variables
    IntentTemplate(
        intent_id="show_env_vars",
        title="Show environment variables",
        patterns=[
            re.compile(r"(?:show|list|print)\s+(?:all\s+)?env(?:ironment)?\s+vars?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="show_env_vars",
            title="Display sorted environment variables",
            command="env | sort",
            explanation="Prints all exported environment variables in alphabetical order.",
            expected_behavior="List of key=value environment variables.",
            safer_alternative="Be cautious when sharing terminal output containing API keys.",
            macos_notes="Standard POSIX env.",
        ),
    ),
    # 26. Show local IP address
    IntentTemplate(
        intent_id="show_local_ip",
        title="Show local IP address",
        patterns=[
            re.compile(r"(?:what\s+is|show|get)\s+(?:my\s+)?(?:local\s+)?ip(?:\s+address)?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="show_local_ip",
            title="Show primary local network IP address",
            command="ipconfig getifaddr en0",
            explanation="Fetches IPv4 address assigned to the primary Wi-Fi/Ethernet interface (en0).",
            expected_behavior="Prints local IPv4 address.",
            safer_alternative=None,
            macos_notes="macOS native ipconfig utility.",
        ),
    ),
    # 27. Show public IP address
    IntentTemplate(
        intent_id="show_public_ip",
        title="Show public IP address",
        patterns=[
            re.compile(r"(?:what\s+is|show|get)\s+(?:my\s+)?public\s+ip", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="show_public_ip",
            title="Query public IP address",
            command="curl -s https://ifconfig.me",
            explanation="Queries public IP resolution service over HTTPS.",
            expected_behavior="Prints external WAN IP address.",
            safer_alternative=None,
            macos_notes="Requires internet connection.",
        ),
    ),
    # 28. Check free disk space
    IntentTemplate(
        intent_id="check_free_disk_space",
        title="Check free disk space",
        patterns=[
            re.compile(r"check\s+(?:free\s+)?disk\s+space", re.I),
            re.compile(r"how\s+much\s+disk\s+space\s+(?:left|free)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="check_free_disk_space",
            title="Display filesystem disk space usage",
            command="df -h /",
            explanation="Reports total, used, and available storage on root volume.",
            expected_behavior="Human-readable disk capacity table.",
            safer_alternative=None,
            macos_notes="Standard macOS BSD df.",
        ),
    ),
    # 29. List processes by memory
    IntentTemplate(
        intent_id="processes_by_memory",
        title="List processes by memory usage",
        patterns=[
            re.compile(r"(?:top|list)\s+processes\s+by\s+memory", re.I),
            re.compile(r"what\s+is\s+using\s+(?:the\s+most\s+)?(?:ram|memory)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="processes_by_memory",
            title="List top processes consuming memory",
            command="ps aux -m | head -n 15",
            explanation="Lists running processes sorted by memory consumption.",
            expected_behavior="Top 15 memory-consuming processes.",
            safer_alternative=None,
            macos_notes="Uses macOS BSD ps -m flag.",
        ),
    ),
    # 30. List processes by CPU
    IntentTemplate(
        intent_id="processes_by_cpu",
        title="List processes by CPU usage",
        patterns=[
            re.compile(r"(?:top|list)\s+processes\s+by\s+cpu", re.I),
            re.compile(r"what\s+is\s+using\s+(?:the\s+most\s+)?cpu", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="processes_by_cpu",
            title="List top processes consuming CPU",
            command="ps aux -r | head -n 15",
            explanation="Lists running processes sorted by CPU usage percentage.",
            expected_behavior="Top 15 CPU-intensive processes.",
            safer_alternative=None,
            macos_notes="Uses macOS BSD ps -r flag.",
        ),
    ),
    # 31. Fix file and directory permissions
    IntentTemplate(
        intent_id="fix_permissions",
        title="Standardize project permissions",
        patterns=[
            re.compile(r"fix\s+permissions(?:\s+in\s+(.+))?", re.I),
            re.compile(r"standardize\s+permissions(?:\s+in\s+(.+))?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="fix_permissions",
            title="Set directories to 755 and files to 644",
            command=f"find {_safe_path(m.group(1) or '.')} -type d -exec chmod 755 {{}} + && find {_safe_path(m.group(1) or '.')} -type f -exec chmod 644 {{}} +",
            explanation="Sets standard permissions (rwxr-xr-x on directories, rw-r--r-- on files).",
            expected_behavior="Updates permissions across hierarchy safely.",
            safer_alternative="Always test on project folders, never on system roots.",
            macos_notes="Standard POSIX chmod.",
        ),
    ),
    # 32. Open folder in Finder
    IntentTemplate(
        intent_id="open_in_finder",
        title="Open directory in macOS Finder",
        patterns=[
            re.compile(r"open\s+(?:this\s+folder|here|folder|directory)?\s*in\s+finder", re.I),
            re.compile(r"reveal\s+in\s+finder\s*(.*)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="open_in_finder",
            title="Reveal directory in Finder",
            command=f"open {_safe_path(m.group(1) if len(m.groups()) > 0 and m.group(1).strip() else '.')}",
            explanation="Launches a new Finder window displaying the directory.",
            expected_behavior="Opens macOS Finder window.",
            safer_alternative=None,
            macos_notes="macOS native open command.",
        ),
    ),
    # 33. Copy file content to clipboard
    IntentTemplate(
        intent_id="copy_file_to_clipboard",
        title="Copy file content to macOS clipboard",
        patterns=[
            re.compile(r"copy\s+(?:content\s+of\s+)?(.+)\s+to\s+(?:the\s+)?clipboard", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="copy_file_to_clipboard",
            title="Pipe file content into macOS pasteboard",
            command=f"pbcopy < {_safe_path(m.group(1))}",
            explanation=f"Pipes the contents of '{m.group(1).strip()}' into pbcopy.",
            expected_behavior="Places file text into macOS system clipboard.",
            safer_alternative=None,
            macos_notes="macOS native pbcopy.",
        ),
    ),
    # 34. Paste clipboard to file
    IntentTemplate(
        intent_id="paste_clipboard_to_file",
        title="Save clipboard content to file",
        patterns=[
            re.compile(r"(?:paste|save)\s+clipboard\s+to\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="paste_clipboard_to_file",
            title="Output macOS clipboard into a file",
            command=f"pbpaste > {_safe_path(m.group(1))}",
            explanation=f"Dumps current pasteboard contents into '{m.group(1).strip()}'.",
            expected_behavior="Creates or overwrites target file with clipboard contents.",
            safer_alternative=f"Use >> {_safe_path(m.group(1))} to append without overwriting existing data.",
            macos_notes="macOS native pbpaste.",
        ),
    ),
    # 35. Update Homebrew packages
    IntentTemplate(
        intent_id="update_homebrew",
        title="Update and upgrade Homebrew",
        patterns=[
            re.compile(r"update\s+brew", re.I),
            re.compile(r"upgrade\s+(?:all\s+)?homebrew\s+packages", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="update_homebrew",
            title="Fetch and upgrade all Homebrew packages",
            command="brew update && brew upgrade && brew cleanup",
            explanation="Updates package definitions, upgrades installed tools, and removes stale downloads.",
            expected_behavior="Upgrades local Homebrew packages.",
            safer_alternative="Run 'brew outdated' first to preview pending updates.",
            macos_notes="Standard Homebrew maintenance.",
        ),
    ),
    # 36. Prune Docker resources
    IntentTemplate(
        intent_id="prune_docker",
        title="Prune unused Docker data",
        patterns=[
            re.compile(r"clean(?:up)?\s+docker", re.I),
            re.compile(r"prune\s+docker\s+(?:images|containers)?", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="prune_docker",
            title="Remove unused Docker containers, networks, and images",
            command="docker system prune -f",
            explanation="Reclaims disk space by removing stopped containers, unused networks, and dangling images.",
            expected_behavior="Deletes unreferenced Docker artifacts.",
            safer_alternative="Omit -f to prompt for confirmation, or run 'docker system df' to inspect space usage.",
            macos_notes="Frees space in Docker VM disk image.",
        ),
    ),
    # 37. Create Python virtual environment
    IntentTemplate(
        intent_id="create_python_venv",
        title="Create Python virtual environment",
        patterns=[
            re.compile(r"create\s+(?:a\s+)?(?:python\s+)?venv(?:\s+named\s+(.+))?", re.I),
            re.compile(r"make\s+(?:a\s+)?virtual\s*env", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="create_python_venv",
            title="Create isolated Python virtual environment",
            command=f"python3 -m venv {_safe_path(m.group(1) if len(m.groups()) > 0 and m.group(1) else '.venv')}",
            explanation="Creates a standalone virtual environment directory containing python and pip.",
            expected_behavior="Initializes virtualenv in target folder.",
            safer_alternative=None,
            macos_notes="Built into Python 3.3+.",
        ),
    ),
    # 38. Clean install Node dependencies (npm ci)
    IntentTemplate(
        intent_id="npm_clean_install",
        title="Clean install Node dependencies",
        patterns=[
            re.compile(r"clean\s+install\s+node\s+(?:deps|dependencies)", re.I),
            re.compile(r"npm\s+clean\s+install", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="npm_clean_install",
            title="Clean install dependencies using package-lock.json",
            command="npm ci",
            explanation="Removes existing node_modules and installs exact locked dependencies cleanly.",
            expected_behavior="Deterministic fresh installation of node_modules.",
            safer_alternative=None,
            macos_notes="Standard npm command.",
        ),
    ),
    # 39. Make script executable
    IntentTemplate(
        intent_id="make_executable",
        title="Make script executable",
        patterns=[
            re.compile(r"make\s+(.+)\s+executable", re.I),
            re.compile(r"chmod\s+\+x\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="make_executable",
            title="Grant execute permissions to file",
            command=f"chmod +x {_safe_path(m.group(1))}",
            explanation=f"Adds execute (+x) permission flag to '{m.group(1).strip()}'.",
            expected_behavior="Allows executing script directly (./script.sh).",
            safer_alternative=None,
            macos_notes="Standard POSIX chmod.",
        ),
    ),
    # 40. Check open file descriptors / file locks
    IntentTemplate(
        intent_id="check_file_locks",
        title="Check who has file open",
        patterns=[
            re.compile(r"who\s+(?:is\s+using|has\s+open)\s+(.+)", re.I),
            re.compile(r"check\s+(?:locks|open\s+handles)\s+on\s+(.+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="check_file_locks",
            title="List processes holding file open",
            command=f"lsof {_safe_path(m.group(1))}",
            explanation=f"Identifies which processes currently have '{m.group(1).strip()}' opened.",
            expected_behavior="Process table showing locking PIDs and command names.",
            safer_alternative=None,
            macos_notes="macOS native lsof.",
        ),
    ),
    # 41. Rename file extensions in bulk
    IntentTemplate(
        intent_id="rename_extension_bulk",
        title="Bulk rename file extensions",
        patterns=[
            re.compile(r"rename\s+(?:\*\.)?([a-zA-Z0-9]+)\s+to\s+(?:\*\.)?([a-zA-Z0-9]+)", re.I),
        ],
        builder=lambda m, text: IntentMatch(
            intent_id="rename_extension_bulk",
            title="Rename all file extensions matching pattern",
            command=f'for f in *.{_safe_ext(m.group(1))}; do [ -f "$f" ] && mv "$f" "${{f%.{_safe_ext(m.group(1))}}}.{_safe_ext(m.group(2))}"; done',
            explanation=f"Iterates over files ending in '.{_safe_ext(m.group(1))}' and renames them to '.{_safe_ext(m.group(2))}'.",
            expected_behavior="Renames matched files safely without subshells.",
            safer_alternative="Use 'fileflow rename' for previewed, journaled, and undoable batch renaming.",
            macos_notes="POSIX shell compatible loop.",
        ),
    ),
]


def match_intent(user_prompt: str) -> IntentMatch | None:
    """Match natural language user prompt against all intent templates."""
    cleaned = user_prompt.strip()
    for tmpl in INTENT_TEMPLATES:
        for pat in tmpl.patterns:
            m = pat.search(cleaned)
            if m:
                res = tmpl.builder(m, cleaned)
                if res:
                    return res
    return None


def list_all_intents() -> list[str]:
    """Return list of all supported intent IDs."""
    return [t.intent_id for t in INTENT_TEMPLATES]
