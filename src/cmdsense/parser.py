"""Resilient shell command tokenizer and AST/segment parser.

Parses compound shell commands (pipes, logical operators, redirections,
command/process substitutions, environment assignments, and command wrappers)
without ever executing anything or raising on malformed input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_ENV_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_FD_REDIRECT_RE = re.compile(r"^(\d*)(>>|>&|>\|?|<|<<|<<<)(.*)$")

OPERATOR_DESCRIPTIONS: dict[str, str] = {
    "|": "Pipe stdout of the left command into stdin of the right command.",
    "|&": "Pipe both stdout and stderr of the left command into stdin of the right command.",
    "&&": "Run the next command only if the previous command exits with status 0 (success).",
    "||": "Run the next command only if the previous command exits with a non-zero status (failure).",
    ";": "Run the next command sequentially regardless of the previous command's exit status.",
    "&": "Run the preceding command asynchronously in the background.",
}

WRAPPER_SPECS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # (standalone_flags, flags_taking_next_arg)
    "sudo": (
        frozenset(
            {
                "-A",
                "-b",
                "-E",
                "-e",
                "-H",
                "-i",
                "-K",
                "-k",
                "-l",
                "-n",
                "-P",
                "-S",
                "-s",
                "-V",
                "-v",
                "--",
            }
        ),
        frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-R", "-r", "-T", "-t", "-U"}),
    ),
    "doas": (
        frozenset({"-L", "-n", "-s", "--"}),
        frozenset({"-u", "-C", "-a"}),
    ),
    "env": (
        frozenset({"-i", "-0", "-v", "-P", "--"}),
        frozenset({"-u", "-C", "-S"}),
    ),
    "time": (
        frozenset({"-p", "-l", "-h", "--"}),
        frozenset({"-o", "-f"}),
    ),
    "nohup": (frozenset({"--"}), frozenset()),
    "nice": (frozenset({"--"}), frozenset({"-n"})),
    "caffeinate": (
        frozenset({"-d", "-i", "-m", "-s", "-u", "--"}),
        frozenset({"-t", "-w"}),
    ),
    "watch": (
        frozenset({"-d", "-t", "-b", "-c", "-e", "-g", "-p", "-x", "--"}),
        frozenset({"-n"}),
    ),
    "xargs": (
        frozenset({"-0", "-o", "-p", "-r", "-t", "-x", "--null", "--no-run-if-empty", "--"}),
        frozenset({"-E", "-I", "-J", "-L", "-n", "-P", "-R", "-S", "-s", "-d", "-a"}),
    ),
    "command": (frozenset({"-p", "-v", "-V", "--"}), frozenset()),
    "builtin": (frozenset({"--"}), frozenset()),
    "exec": (frozenset({"-c", "-l", "--"}), frozenset({"-a"})),
}

SUBCOMMAND_TOOLS: frozenset[str] = frozenset(
    {
        "git",
        "docker",
        "docker-compose",
        "brew",
        "npm",
        "pnpm",
        "yarn",
        "pip",
        "pip3",
        "uv",
        "gh",
        "diskutil",
        "launchctl",
        "defaults",
        "networksetup",
        "security",
        "codesign",
        "tmutil",
        "csrutil",
        "softwareupdate",
        "scutil",
        "hdiutil",
        "xcode-select",
        "xcrun",
        "openssl",
    }
)


@dataclass(frozen=True)
class Token:
    """A single lexical token in a command segment."""

    value: str
    raw: str
    quoted: bool = False
    quote_char: str | None = None
    has_expansion: bool = False


@dataclass(frozen=True)
class Redirection:
    """An I/O redirection attached to a command segment."""

    op: str
    target: str
    fd: str | None
    raw: str
    description: str

    @property
    def symbol(self) -> str:
        return self.op


@dataclass(frozen=True)
class Substitution:
    """A command or process substitution embedded in a segment."""

    kind: str  # "command_sub" | "backtick" | "process_sub"
    raw: str
    inner_command: str
    parsed: CommandLine | None = None

    @property
    def inner(self) -> str:
        return self.inner_command


@dataclass(frozen=True)
class WrapperInfo:
    """A prefix wrapper command (such as sudo, env, xargs, time, nohup)."""

    name: str
    flags: list[str] = field(default_factory=list)
    env_assignments: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Segment:
    """One pipeline or chained command segment."""

    index: int
    raw: str
    operator_before: str | None = None
    operator_after: str | None = None
    env_vars: list[tuple[str, str]] = field(default_factory=list)
    wrappers: list[WrapperInfo] = field(default_factory=list)
    executable: str | None = None
    raw_executable: str | None = None
    subcommand: str | None = None
    args: list[str] = field(default_factory=list)
    arg_tokens: list[Token] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    redirections: list[Redirection] = field(default_factory=list)
    substitutions: list[Substitution] = field(default_factory=list)
    is_subshell: bool = False

    @property
    def command(self) -> str:
        return self.executable or ""

    @property
    def effective_command(self) -> str:
        return self.executable or ""

    @property
    def arguments(self) -> list[str]:
        return self.args

    @property
    def raw_text(self) -> str:
        return self.raw

    @property
    def operator(self) -> str | None:
        return self.operator_after

    @property
    def wrapper_name(self) -> str | None:
        return self.wrappers[0].name if self.wrappers else None

    @property
    def is_sudo(self) -> bool:
        return any(w.name in ("sudo", "doas") for w in self.wrappers)


@dataclass
class CommandLine:
    """Parsed representation of a complete shell command line."""

    raw: str
    segments: list[Segment] = field(default_factory=list)
    operators: list[str] = field(default_factory=list)
    parse_error: str | None = None
    has_pipes: bool = False
    has_chaining: bool = False
    has_redirections: bool = False
    has_substitutions: bool = False
    has_subshells: bool = False


@dataclass
class _LexItem:
    kind: str  # "token" | "op" | "redir"
    value: str
    raw: str
    quoted: bool = False
    quote_char: str | None = None
    has_expansion: bool = False
    substitutions: list[tuple[str, str, str]] = field(default_factory=list)


def _describe_redirection(fd: str | None, op: str, target: str) -> str:
    stream = "stdout"
    if fd == "0" or op in ("<", "<<", "<<<"):
        stream = "stdin"
    elif fd == "2":
        stream = "stderr"
    elif fd == "&" or op in ("&>", "&>>"):
        stream = "both stdout and stderr"
    elif fd:
        stream = f"file descriptor {fd}"

    if op in {">>>", "<<<"}:
        return f"Feed literal here-string {target!r} into {stream}."
    if op == "<<":
        return f"Read here-document delimited by {target!r} into {stream}."
    if op == "<":
        return f"Read {stream} from file {target!r}."
    if op in (">>", "&>>"):
        return f"Append {stream} to file {target!r} (creates file if missing)."
    if op == ">&":
        if target.startswith("&") or target.isdigit():
            dest = target.lstrip("&")
            dest_name = {
                "1": "stdout (fd 1)",
                "2": "stderr (fd 2)",
                "0": "stdin (fd 0)",
                "-": "closed stream",
            }.get(dest, f"fd {dest}")
            return f"Redirect {stream} to {dest_name}."
        return f"Redirect {stream} to {target!r}."
    if op == ">|":
        return f"Force-overwrite {target!r} with {stream} (ignores noclobber)."
    return f"Redirect {stream} to overwrite file {target!r} (truncates existing content)."


def _extract_balanced(text: str, start: int, open_ch: str, close_ch: str) -> tuple[str, int, bool]:
    """Read from start (pointing after open_ch) until matching close_ch."""
    depth = 1
    i = start
    n = len(text)
    in_single = False
    in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1, True
        i += 1
    return text[start:], n, False


def _extract_backtick(text: str, start: int) -> tuple[str, int, bool]:
    """Read from start (pointing after opening `) until closing `."""
    i = start
    n = len(text)
    buf: list[str] = []
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] in ("`", "\\", "$"):
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "`":
            return "".join(buf), i + 1, True
        buf.append(ch)
        i += 1
    return "".join(buf), n, False


def _lex_command(text: str) -> tuple[list[_LexItem], list[str]]:
    """Tokenize shell input into tokens, operators, and redirection operators."""
    # Join backslash-newline line continuations outside single quotes
    cleaned = re.sub(r"\\\r?\n", " ", text)
    items: list[_LexItem] = []
    errors: list[str] = []

    val_buf: list[str] = []
    raw_buf: list[str] = []
    token_quoted = False
    token_quote_chars: set[str] = set()
    token_has_expansion = False
    token_subs: list[tuple[str, str, str]] = []

    def flush_token() -> None:
        nonlocal token_quoted, token_has_expansion
        if not raw_buf and not token_quoted:
            return
        q_char: str | None = None
        if len(token_quote_chars) == 1:
            q_char = next(iter(token_quote_chars))
        elif len(token_quote_chars) > 1:
            q_char = "mixed"
        items.append(
            _LexItem(
                kind="token",
                value="".join(val_buf),
                raw="".join(raw_buf),
                quoted=token_quoted,
                quote_char=q_char,
                has_expansion=token_has_expansion,
                substitutions=list(token_subs),
            )
        )
        val_buf.clear()
        raw_buf.clear()
        token_quoted = False
        token_quote_chars.clear()
        token_has_expansion = False
        token_subs.clear()

    i = 0
    n = len(cleaned)
    while i < n:
        ch = cleaned[i]

        # Whitespace outside quotes
        if ch in (" ", "\t", "\r"):
            flush_token()
            i += 1
            continue

        # Newline acts like ; command separator
        if ch == "\n":
            flush_token()
            if items and items[-1].kind != "op":
                items.append(_LexItem(kind="op", value=";", raw="\n"))
            i += 1
            continue

        # Comment at start of a token
        if ch == "#" and not raw_buf:
            while i < n and cleaned[i] != "\n":
                i += 1
            continue

        # Single quotes
        if ch == "'":
            token_quoted = True
            token_quote_chars.add("'")
            raw_buf.append("'")
            i += 1
            closed = False
            while i < n:
                if cleaned[i] == "'":
                    raw_buf.append("'")
                    i += 1
                    closed = True
                    break
                val_buf.append(cleaned[i])
                raw_buf.append(cleaned[i])
                i += 1
            if not closed:
                errors.append("Unclosed single quote (') in command line.")
            continue

        # Double quotes
        if ch == '"':
            token_quoted = True
            token_quote_chars.add('"')
            raw_buf.append('"')
            i += 1
            closed = False
            while i < n:
                c = cleaned[i]
                if c == '"':
                    raw_buf.append('"')
                    i += 1
                    closed = True
                    break
                if c == "\\" and i + 1 < n:
                    nxt = cleaned[i + 1]
                    raw_buf.append(c + nxt)
                    if nxt in ('"', "\\", "$", "`"):
                        val_buf.append(nxt)
                    else:
                        val_buf.append(c + nxt)
                    i += 2
                    continue
                if c == "$" and i + 1 < n and cleaned[i + 1] == "(":
                    inner, next_i, ok = _extract_balanced(cleaned, i + 2, "(", ")")
                    raw_sub = cleaned[i:next_i]
                    val_buf.append(raw_sub)
                    raw_buf.append(raw_sub)
                    token_has_expansion = True
                    token_subs.append(("command_sub", raw_sub, inner))
                    if not ok:
                        errors.append("Unclosed command substitution '$(' inside double quotes.")
                    i = next_i
                    continue
                if c == "`":
                    inner, next_i, ok = _extract_backtick(cleaned, i + 1)
                    raw_sub = cleaned[i:next_i]
                    val_buf.append(raw_sub)
                    raw_buf.append(raw_sub)
                    token_has_expansion = True
                    token_subs.append(("backtick", raw_sub, inner))
                    if not ok:
                        errors.append(
                            "Unclosed backtick command substitution (`) inside double quotes."
                        )
                    i = next_i
                    continue
                if (
                    c == "$"
                    and i + 1 < n
                    and (cleaned[i + 1].isalpha() or cleaned[i + 1] in ("_", "{"))
                ):
                    token_has_expansion = True
                val_buf.append(c)
                raw_buf.append(c)
                i += 1
            if not closed:
                errors.append('Unclosed double quote (") in command line.')
            continue

        # Backslash escape outside quotes
        if ch == "\\":
            if i + 1 < n:
                nxt = cleaned[i + 1]
                val_buf.append(nxt)
                raw_buf.append("\\" + nxt)
                token_quoted = True
                i += 2
            else:
                errors.append("Trailing backslash (\\) at end of command line.")
                val_buf.append("\\")
                raw_buf.append("\\")
                i += 1
            continue

        # Process substitution <(...) or >(...)
        if ch in ("<", ">") and i + 1 < n and cleaned[i + 1] == "(":
            inner, next_i, ok = _extract_balanced(cleaned, i + 2, "(", ")")
            raw_sub = cleaned[i:next_i]
            val_buf.append(raw_sub)
            raw_buf.append(raw_sub)
            token_has_expansion = True
            token_subs.append(("process_sub", raw_sub, inner))
            if not ok:
                errors.append(f"Unclosed process substitution '{ch}(' in command line.")
            i = next_i
            continue

        # Command substitution $(...) outside quotes
        if ch == "$" and i + 1 < n and cleaned[i + 1] == "(":
            inner, next_i, ok = _extract_balanced(cleaned, i + 2, "(", ")")
            raw_sub = cleaned[i:next_i]
            val_buf.append(raw_sub)
            raw_buf.append(raw_sub)
            token_has_expansion = True
            token_subs.append(("command_sub", raw_sub, inner))
            if not ok:
                errors.append("Unclosed command substitution '$(' in command line.")
            i = next_i
            continue

        # Backtick substitution `...` outside quotes
        if ch == "`":
            inner, next_i, ok = _extract_backtick(cleaned, i + 1)
            raw_sub = cleaned[i:next_i]
            val_buf.append(raw_sub)
            raw_buf.append(raw_sub)
            token_has_expansion = True
            token_subs.append(("backtick", raw_sub, inner))
            if not ok:
                errors.append("Unclosed backtick substitution (`) in command line.")
            i = next_i
            continue

        # Subshell group (...) at token boundary
        if ch == "(" and not raw_buf:
            # Check fork bomb pattern :(){ :|:& };: before treating as subshell
            if items and items[-1].kind == "token" and items[-1].value.endswith(":"):
                val_buf.append(ch)
                raw_buf.append(ch)
                i += 1
                continue
            inner, next_i, ok = _extract_balanced(cleaned, i + 1, "(", ")")
            raw_sub = cleaned[i:next_i]
            val_buf.append(raw_sub)
            raw_buf.append(raw_sub)
            token_has_expansion = True
            token_subs.append(("subshell", raw_sub, inner))
            if not ok:
                errors.append("Unclosed subshell '(' in command line.")
            flush_token()
            i = next_i
            continue

        # Redirection with optional leading file descriptor (e.g. 2>&1, 2>/dev/null, >>out, &>>out)
        if ch in ("<", ">") or (ch == "&" and i + 1 < n and cleaned[i + 1] == ">" and not raw_buf):
            # If current buffer is purely digits (e.g. "2" before ">"), it's an fd prefix
            fd_prefix = ""
            if raw_buf and "".join(raw_buf).isdigit() and not token_quoted:
                fd_prefix = "".join(raw_buf)
                val_buf.clear()
                raw_buf.clear()
            else:
                flush_token()

            if ch == "&":
                if cleaned.startswith("&>>", i):
                    op = "&>>"
                    i += 3
                else:
                    op = "&>"
                    i += 2
                items.append(_LexItem(kind="redir", value=op, raw=op))
                continue

            if cleaned.startswith("<<<", i):
                op = "<<<"
                i += 3
            elif cleaned.startswith("<<", i):
                op = "<<"
                i += 2
            elif cleaned.startswith(">>", i):
                op = ">>"
                i += 2
            elif cleaned.startswith(">&", i):
                op = ">&"
                i += 2
            elif cleaned.startswith(">|", i):
                op = ">|"
                i += 2
            elif cleaned.startswith("<>", i):
                op = "<>"
                i += 2
            else:
                op = ch
                i += 1

            full_op = f"{fd_prefix}{op}"
            items.append(_LexItem(kind="redir", value=full_op, raw=full_op))
            continue

        # Multi-character and single-character control operators: &&, ||, |&, |, ;, &
        if ch in ("|", "&", ";"):
            flush_token()
            if cleaned.startswith("&&", i):
                items.append(_LexItem(kind="op", value="&&", raw="&&"))
                i += 2
            elif cleaned.startswith("||", i):
                items.append(_LexItem(kind="op", value="||", raw="||"))
                i += 2
            elif cleaned.startswith("|&", i):
                items.append(_LexItem(kind="op", value="|&", raw="|&"))
                i += 2
            else:
                items.append(_LexItem(kind="op", value=ch, raw=ch))
                i += 1
            continue

        if ch == "$" and i + 1 < n and (cleaned[i + 1].isalpha() or cleaned[i + 1] in ("_", "{")):
            token_has_expansion = True

        val_buf.append(ch)
        raw_buf.append(ch)
        i += 1

    flush_token()
    return items, errors


def _build_segment(
    index: int,
    seg_items: list[_LexItem],
    op_before: str | None,
    op_after: str | None,
    depth: int,
) -> tuple[Segment, list[str]]:
    errors: list[str] = []
    tokens: list[Token] = []
    redirections: list[Redirection] = []
    substitutions: list[Substitution] = []
    is_subshell = False

    i = 0
    n = len(seg_items)
    while i < n:
        item = seg_items[i]
        if item.kind == "redir":
            m = _FD_REDIRECT_RE.match(item.value)
            if m:
                fd_part, op_part, rest = m.group(1), m.group(2), m.group(3)
                fd: str | None = fd_part if fd_part else None
            elif item.value in ("&>", "&>>"):
                fd = "&"
                op_part = item.value
                rest = ""
            else:
                fd = None
                op_part = item.value
                rest = ""

            target = rest
            raw_redir = item.raw
            if not target:
                if i + 1 < n and seg_items[i + 1].kind == "token":
                    nxt_tok = seg_items[i + 1]
                    target = nxt_tok.value
                    raw_redir = f"{item.raw} {nxt_tok.raw}"
                    for sub_kind, sub_raw, sub_inner in nxt_tok.substitutions:
                        parsed_inner = (
                            parse_command(sub_inner, _depth=depth + 1)
                            if depth < 4 and sub_inner.strip()
                            else None
                        )
                        substitutions.append(
                            Substitution(
                                kind=sub_kind,
                                raw=sub_raw,
                                inner_command=sub_inner,
                                parsed=parsed_inner,
                            )
                        )
                    i += 1
                else:
                    target = "(missing target)"
                    errors.append(f"Redirection operator '{item.raw}' is missing a target.")
            redirections.append(
                Redirection(
                    op=op_part,
                    target=target,
                    fd=fd,
                    raw=raw_redir,
                    description=_describe_redirection(fd, op_part, target),
                )
            )
            i += 1
            continue

        if item.kind == "token":
            tok = Token(
                value=item.value,
                raw=item.raw,
                quoted=item.quoted,
                quote_char=item.quote_char,
                has_expansion=item.has_expansion,
            )
            tokens.append(tok)
            for sub_kind, sub_raw, sub_inner in item.substitutions:
                if sub_kind == "subshell":
                    is_subshell = True
                parsed_inner = (
                    parse_command(sub_inner, _depth=depth + 1)
                    if depth < 4 and sub_inner.strip()
                    else None
                )
                substitutions.append(
                    Substitution(
                        kind=sub_kind,
                        raw=sub_raw,
                        inner_command=sub_inner,
                        parsed=parsed_inner,
                    )
                )
        i += 1

    # Extract leading environment variable assignments and command wrappers
    env_vars: list[tuple[str, str]] = []
    wrappers: list[WrapperInfo] = []
    pos = 0
    total_tokens = len(tokens)

    while pos < total_tokens:
        t = tokens[pos]
        m = _ENV_ASSIGN_RE.match(t.value)
        if m and not t.raw.startswith(("'", '"')):
            env_vars.append((m.group(1), m.group(2)))
            pos += 1
        else:
            break

    # Unwrap wrapper commands (sudo, env, time, nohup, nice, caffeinate, watch, xargs, etc.)
    while pos < total_tokens:
        cmd_token = tokens[pos]
        base_name = Path(cmd_token.value).name
        if base_name not in WRAPPER_SPECS:
            break

        standalone_flags, arg_flags = WRAPPER_SPECS[base_name]
        w_flags: list[str] = []
        w_envs: list[tuple[str, str]] = []
        scan = pos + 1
        while scan < total_tokens:
            ft = tokens[scan]
            fval = ft.value
            if base_name == "env":
                env_m = _ENV_ASSIGN_RE.match(fval)
                if env_m and not ft.raw.startswith(("'", '"')):
                    w_envs.append((env_m.group(1), env_m.group(2)))
                    scan += 1
                    continue
            if fval == "--":
                w_flags.append(fval)
                scan += 1
                break
            if fval in arg_flags:
                w_flags.append(fval)
                if scan + 1 < total_tokens:
                    w_flags.append(tokens[scan + 1].value)
                    scan += 2
                else:
                    scan += 1
                continue
            if fval in standalone_flags or (
                fval.startswith("-")
                and len(fval) > 1
                and not fval.startswith("--")
                and all(f"-{c}" in standalone_flags for c in fval[1:])
            ):
                w_flags.append(fval)
                scan += 1
                continue
            # Also handle attached flag values like -n1 or -uuser for nice/sudo/xargs
            if fval.startswith("-") and len(fval) > 2 and fval[:2] in arg_flags:
                w_flags.append(fval)
                scan += 1
                continue
            break

        # Only treat as a wrapper if another command follows it!
        if scan < total_tokens:
            wrappers.append(WrapperInfo(name=base_name, flags=w_flags, env_assignments=w_envs))
            env_vars.extend(w_envs)
            pos = scan
        else:
            break

    raw_executable: str | None = None
    executable: str | None = None
    subcommand: str | None = None
    arg_tokens: list[Token] = []

    if pos < total_tokens:
        raw_executable = tokens[pos].value
        executable = Path(raw_executable).name if raw_executable else None
        arg_tokens = tokens[pos + 1 :]
        if executable in SUBCOMMAND_TOOLS:
            # Find the first non-flag argument as subcommand
            for atok in arg_tokens:
                if not atok.value.startswith("-"):
                    subcommand = atok.value
                    break

    raw_segment_parts = [it.raw for it in seg_items]
    seg = Segment(
        index=index,
        raw=" ".join(raw_segment_parts).strip(),
        operator_before=op_before,
        operator_after=op_after,
        env_vars=env_vars,
        wrappers=wrappers,
        executable=executable,
        raw_executable=raw_executable,
        subcommand=subcommand,
        args=[t.value for t in arg_tokens],
        arg_tokens=arg_tokens,
        tokens=tokens,
        redirections=redirections,
        substitutions=substitutions,
        is_subshell=is_subshell,
    )
    return seg, errors


def parse_command(command: str, *, _depth: int = 0) -> CommandLine:
    """Parse a shell command line into segments, operators, redirections, and substitutions.

    Never raises an exception on malformed input; records any syntax problem in
    :attr:`CommandLine.parse_error` while still returning best-effort segments.
    """
    raw = command.strip()
    if not raw:
        return CommandLine(raw=command, parse_error="Command is empty.")

    items, lex_errors = _lex_command(raw)
    if not items:
        return CommandLine(
            raw=command,
            parse_error=lex_errors[0] if lex_errors else "Command contains no executable tokens.",
        )

    raw_segments: list[list[_LexItem]] = []
    operators: list[str] = []
    current: list[_LexItem] = []

    for item in items:
        if item.kind == "op":
            if item.value == "&" and not current:
                lex_errors.append("Unexpected leading '&' operator.")
                continue
            if not current:
                lex_errors.append(f"Unexpected operator '{item.raw}' with no preceding command.")
                continue
            raw_segments.append(current)
            operators.append(item.value)
            current = []
        else:
            current.append(item)

    if current:
        raw_segments.append(current)
    elif operators and operators[-1] not in ("&", ";"):
        lex_errors.append(f"Command ends with dangling operator '{operators[-1]}'.")

    segments: list[Segment] = []
    for idx, seg_items in enumerate(raw_segments):
        op_before = operators[idx - 1] if idx > 0 else None
        op_after = operators[idx] if idx < len(operators) else None
        seg, seg_errs = _build_segment(idx, seg_items, op_before, op_after, _depth)
        lex_errors.extend(seg_errs)
        segments.append(seg)

    has_pipes = any(op in ("|", "|&") for op in operators)
    has_chaining = any(op in ("&&", "||", ";", "&") for op in operators)
    has_redirections = any(bool(s.redirections) for s in segments)
    has_substitutions = any(bool(s.substitutions) for s in segments)
    has_subshells = any(s.is_subshell for s in segments)

    return CommandLine(
        raw=command,
        segments=segments,
        operators=operators,
        parse_error="; ".join(dict.fromkeys(lex_errors)) if lex_errors else None,
        has_pipes=has_pipes,
        has_chaining=has_chaining,
        has_redirections=has_redirections,
        has_substitutions=has_substitutions,
        has_subshells=has_subshells,
    )


parse_command_line = parse_command
