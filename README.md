# CmdSense (`cmdsense`)

> Terminal Command Intelligence, Explanation, Safe Suggestions, Error Diagnosis & Static Safety Analysis

[![CI](https://github.com/VinitSurve/cmdsense/actions/workflows/ci.yml/badge.svg)](https://github.com/VinitSurve/cmdsense/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)

`cmdsense` is a local-first CLI intelligence utility designed for developers and systems engineers working on macOS and POSIX systems. It breaks down complex shell pipelines, explains commands flag-by-flag, suggests safe commands from natural language requests, diagnoses terminal stack traces with secret redaction, and evaluates security risks across five risk tiers.

> **Cardinal Security Rule:** `cmdsense` **never** executes, runs, or evaluates any analyzed or suggested command.

---

## Features

- **Pipeline & Flag Explanation:** Deconstructs complex POSIX pipelines, subshells, command substitutions (`$(cmd)`), redirections (`2>&1`), and command wrappers (`sudo`, `env`, `nohup`, `caffeinate`, `xargs`).
- **92 macOS & POSIX Command Specs:** Comprehensive knowledge catalog spanning filesystem tools, text processing, network tools, process monitoring, git, docker, and native macOS utilities (`pbcopy`, `diskutil`, `open`, `sw_vers`). Highlights macOS BSD flag differences from GNU equivalents.
- **Natural Language Command Builder (41 Intents):** Converts requests like *"find files larger than 100MB"*, *"kill process on port 3000"*, or *"undo last git commit"* into safe shell commands with strict `shlex.quote` injection resistance.
- **Error Diagnosis & Secret Redaction (54 Signatures):** Parses stack traces from Python, Node.js, Git, Docker, and shell errors. Redacts sensitive credentials (API tokens, private keys, passwords) and provides ordered, actionable remedies.
- **Static Safety Analyzer (5 Risk Tiers):** Classifies commands as `INFORMATIONAL`, `LOW`, `MODERATE`, `HIGH`, or `DESTRUCTIVE`. Warns against remote script piping (`curl | bash`), raw disk device writes (`dd`), root deletions (`rm -rf /`), fork bombs, and credential leaks in command arguments.
- **Opt-In Local AI Client:** Optional integration with local Ollama (`http://localhost:11434`) or OpenAI-compatible endpoints with loopback security restrictions, automated secret masking, and disclaimers.

---

## Installation

### Using pipx (Recommended for standalone CLI use)

```bash
pipx install git+https://github.com/VinitSurve/cmdsense.git
```

Or install from a local checkout:

```bash
git clone https://github.com/VinitSurve/cmdsense.git
cd cmdsense
pipx install .
```

### Using pip (in an active virtual environment)

```bash
pip install .
```

---

## Quick Start

```bash
# Explain a complex pipeline flag-by-flag
cmdsense explain "find . -type f -name '*.py' | xargs wc -l"

# Convert natural language to a safe shell command
cmdsense suggest "Find all files larger than 100MB in ~/Downloads"

# Evaluate risk and destructive potential of a command
cmdsense safety "curl -sL https://install.example.com | sudo bash"

# Diagnose a terminal error message or stack trace
npm start 2>&1 | cmdsense diagnose
cmdsense diagnose --text "Error: listen EADDRINUSE :::3000"

# Launch guided interactive assistant
cmdsense interactive
```

---

## Command Reference

| Command | Description |
|---|---|
| `cmdsense explain "CMD"` | Decompose and explain shell commands, operators, pipelines, and flags. |
| `cmdsense suggest "QUERY"` | Suggest a safe macOS/POSIX command from a natural language task description. |
| `cmdsense diagnose` | Diagnose terminal error output piped from stdin or passed via `--text`/`--file`. |
| `cmdsense safety "CMD"` | Perform static security analysis and output risk tier and safer alternatives. |
| `cmdsense ai [status\|test]` | Inspect or test optional local AI model backend configuration. |
| `cmdsense interactive` | Launch guided terminal intelligence loop. |
| `cmdsense config` | View and edit `cmdsense` configuration. |

### Global Flags

- `--json`: Output machine-readable JSON on `stdout`.
- `--quiet`: Suppress banners, headings, and decoration.
- `--verbose`: Print diagnostic debugging details to `stderr`.
- `--no-color`: Disable ANSI color escapes (respects `NO_COLOR=1`).
- `--help`, `-h`: Show usage assistance.
- `--version`: Display `cmdsense` version.

### Safety Risk Tiers & Exit Codes

`cmdsense safety` evaluates commands and exits with specific codes suitable for shell scripts and CI/CD pipelines:
- `0`: `INFORMATIONAL`, `LOW`, or `MODERATE` risk.
- `1`: `HIGH` risk (e.g. commands with credential arguments or broad modifications).
- `2`: `DESTRUCTIVE` risk (e.g. `rm -rf /`, `curl | bash`, raw disk writes, or fork bombs).

---

## Configuration & Storage

`cmdsense` stores its configuration in macOS platform directories:
- **Config:** `~/Library/Application Support/devtoolkit/cmdsense/config.json`
- **Logs:** `~/Library/Logs/devtoolkit/cmdsense/cmdsense.log`

Override with `DEVTOOLKIT_HOME=/custom/path`.

Example configuration management:
```bash
# View configuration
cmdsense config show

# Enable optional local Ollama AI backend
cmdsense config set ai_enabled true
cmdsense config set ai_provider ollama
cmdsense config set ai_endpoint "http://localhost:11434"
cmdsense config set ai_model "llama3.2"

# Reset configuration to defaults
cmdsense config reset --yes
```

---

## Security Guarantees & Disclaimers

1. **Zero Execution:** `cmdsense` is an analytical tool. It never runs commands on your behalf under any circumstances.
2. **Injection Resistance:** Intent builders sanitize path arguments and wrap variable parameters using `shlex.quote`.
3. **Secret Masking:** Terminal error traces and prompts sent to optional AI backends are scrubbed with high-entropy credential patterns (Bearer tokens, API keys, passwords).
4. **Static Analysis Disclaimer:** Static safety analysis is heuristic and pattern-based. It cannot guarantee that an unflagged command is completely free of unintended side effects. Always inspect commands before executing.

---

## Development Setup

```bash
git clone https://github.com/VinitSurve/cmdsense.git
cd cmdsense
make dev
make test
make check
```

---

## Running Tests

```bash
# Run pytest suite
pytest -v

# Run fast unit tests
pytest -m "not slow" -q
```

---

## Known Limitations

- **Shell Parser Scope:** The AST parser handles standard POSIX and Bash/Zsh syntax. Highly dynamic shell expansions (such as `eval` statements evaluating complex calculated variables) cannot be fully analyzed statically.

---

## License

This project is licensed under the [MIT License](LICENSE).
