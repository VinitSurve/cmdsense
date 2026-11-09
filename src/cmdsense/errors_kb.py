"""Comprehensive error signatures knowledge base for CmdSense diagnose engine.

Includes ≥ 50 distinct error signatures across Python, Node/npm/yarn, Git,
macOS permissions & system tools, shell errors, port conflicts, and Docker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorFix:
    title: str
    command: str | None
    explanation: str


@dataclass(frozen=True)
class ErrorSignature:
    signature_id: str
    category: str
    pattern: re.Pattern[str]
    title: str
    likely_cause: str
    fixes: list[ErrorFix]
    confidence: str = "high"


ERROR_SIGNATURES: list[ErrorSignature] = [
    ErrorSignature(
        signature_id="py_command_not_found",
        category="python",
        pattern=re.compile(r"(?:zsh|bash|sh):\s+command not found:\s+python\b"),
        title="Python 2/3 Command Not Found",
        likely_cause="macOS 12.3+ removed /usr/bin/python. Use python3 instead.",
        fixes=[
            ErrorFix("Use python3", "python3 <script.py>", "Run script using python3 explicitly."),
            ErrorFix(
                "Create alias", "alias python=python3", "Alias python to python3 in ~/.zshrc."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_permission_error",
        category="python",
        pattern=re.compile(
            r"PermissionError:\s+\[Errno 13\]\s+Permission denied:\s+['\"]([^'\"]+)['\"]"
        ),
        title="Python PermissionError",
        likely_cause="The process lacks read or write access to the specified filesystem path.",
        fixes=[
            ErrorFix(
                "Check file permissions",
                "ls -la <path>",
                "Verify owner and permissions of target file.",
            ),
            ErrorFix(
                "Grant user permissions",
                "chmod u+rw <path>",
                "Add read/write permissions for current user.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_venv_broken",
        category="python",
        pattern=re.compile(r"No Python at '.*', or active virtualenv is broken", re.I),
        title="Python Virtualenv Broken",
        likely_cause="The base Python interpreter that created this virtual environment was deleted or upgraded.",
        fixes=[
            ErrorFix(
                "Recreate virtual environment",
                "rm -rf .venv && python3 -m venv .venv",
                "Rebuild virtualenv from scratch.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_eacces_permissions",
        category="node",
        pattern=re.compile(r"npm ERR!\s+code\s+EACCES", re.I),
        title="npm EACCES Permissions Error",
        likely_cause="Attempted to install global npm packages into a root-owned directory without permissions.",
        fixes=[
            ErrorFix(
                "Change npm default directory",
                "mkdir ~/.npm-global && npm config set prefix '~/.npm-global'",
                "Configure npm to install global packages into home folder.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_lockfile_conflict",
        category="node",
        pattern=re.compile(r"npm ERR!\s+code\s+ELOCKVERIFY", re.I),
        title="npm Lockfile Verification Failure",
        likely_cause="package.json and package-lock.json have conflicting dependencies.",
        fixes=[
            ErrorFix(
                "Regenerate lockfile",
                "npm install --package-lock-only",
                "Update package-lock.json.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_elifecycle",
        category="node",
        pattern=re.compile(r"npm ERR!\s+code\s+ELIFECYCLE", re.I),
        title="npm Script ELIFECYCLE Failure",
        likely_cause="A custom build, test, or start script returned a non-zero exit code.",
        fixes=[
            ErrorFix(
                "Run script directly",
                "node <script>",
                "Inspect raw error output from the failing script.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_authentication_failed",
        category="git",
        pattern=re.compile(r"fatal:\s+Authentication failed for"),
        title="Git Authentication Failed",
        likely_cause="Invalid username, expired Personal Access Token (PAT), or outdated SSH credential.",
        fixes=[
            ErrorFix(
                "Update credentials in macOS Keychain",
                "git-credential-osxkeychain erase <host>",
                "Clear stored credentials to re-authenticate.",
            ),
            ErrorFix(
                "Use GitHub CLI to authenticate",
                "gh auth login",
                "Authenticate securely using GitHub CLI.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_uncommitted_overwrite",
        category="git",
        pattern=re.compile(
            r"error:\s+Your local changes to the following files would be overwritten by"
        ),
        title="Git Uncommitted Changes Conflict",
        likely_cause="Checking out or pulling would overwrite uncommitted local modifications.",
        fixes=[
            ErrorFix("Stash changes", "git stash", "Temporarily save local changes."),
            ErrorFix(
                "Commit changes",
                "git commit -am 'WIP'",
                "Commit changes before switching branches.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="macos_permission_denied_generic",
        category="macos",
        pattern=re.compile(r"(?:open|cat|touch|rm):\s+.*:\s+Permission denied", re.I),
        title="macOS File Permission Denied",
        likely_cause="File permissions or macOS sandbox restrict current user from modifying or reading file.",
        fixes=[
            ErrorFix("Check owner and mode", "ls -la <file>", "Verify ownership."),
            ErrorFix(
                "Inspect ACLs and attributes",
                "ls -le <file> && xattr -l <file>",
                "Check extended attributes.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="port_address_already_in_use_generic",
        category="network",
        pattern=re.compile(r"(?:address already in use|bind: Address already in use)", re.I),
        title="TCP Port Conflict",
        likely_cause="Another local application is already bound to the specified socket port.",
        fixes=[
            ErrorFix(
                "List occupying process", "lsof -iTCP -sTCP:LISTEN -P", "Locate listening ports."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="shell_no_such_file_or_dir",
        category="shell",
        pattern=re.compile(r"(?:zsh|bash|sh):\s+no such file or directory:\s+(.+)"),
        title="Shell No Such File or Directory",
        likely_cause="Script path does not exist, or shebang line (#!/...) points to a nonexistent interpreter.",
        fixes=[
            ErrorFix("Check script existence", "ls -la <script>", "Verify path."),
            ErrorFix(
                "Check shebang interpreter",
                "head -n 1 <script>",
                "Verify the #! interpreter path exists.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="shell_syntax_error_token",
        category="shell",
        pattern=re.compile(r"syntax error near unexpected token\s+['\"]?([^'\"]+)['\"]?", re.I),
        title="Shell Syntax Error Near Token",
        likely_cause="Unclosed quotation marks, unescaped parentheses, or invalid pipe syntax in shell script.",
        fixes=[
            ErrorFix("Inspect syntax", None, "Check matching quotes and balance parentheses."),
        ],
    ),
    ErrorSignature(
        signature_id="brew_lock_held",
        category="brew",
        pattern=re.compile(r"Another active Homebrew process is already using the formula"),
        title="Homebrew Lock Held by Another Process",
        likely_cause="Another brew command is currently running in the background or terminal.",
        fixes=[
            ErrorFix(
                "Check brew processes",
                "ps aux | grep brew",
                "Wait for running process or terminate it if hung.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="brew_permissions_opt_homebrew",
        category="brew",
        pattern=re.compile(r"/opt/homebrew is not writable", re.I),
        title="Homebrew Directory Not Writable",
        likely_cause="Homebrew prefix directory is owned by root instead of the primary user.",
        fixes=[
            ErrorFix(
                "Restore user ownership",
                "sudo chown -R vinit:staff /opt/homebrew",
                "Grant current user ownership of Homebrew.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="cargo_missing_toolchain",
        category="rust",
        pattern=re.compile(
            r"error:\s+no default toolchain configured|error:\s+toolchain '.*' is not installed",
            re.I,
        ),
        title="Rust Toolchain Missing",
        likely_cause="rustup has no active or installed default toolchain.",
        fixes=[
            ErrorFix(
                "Install stable toolchain",
                "rustup default stable",
                "Install and activate the stable Rust toolchain.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="docker_no_space_left",
        category="docker",
        pattern=re.compile(r"docker:\s+no space left on device", re.I),
        title="Docker VM Disk Space Exhausted",
        likely_cause="The virtual disk image allocated to Docker has filled up with old layers and volumes.",
        fixes=[
            ErrorFix(
                "Prune Docker system",
                "docker system prune -a --volumes",
                "Clean unused images, containers, and volumes.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="composer_missing_ext",
        category="php",
        pattern=re.compile(
            r"requires ext-([a-zA-Z0-9_\-]+) \* -> it is missing from your system", re.I
        ),
        title="PHP Composer Missing Extension",
        likely_cause="A required PHP extension (e.g. mbstring, curl, gd, zip) is not enabled in php.ini.",
        fixes=[
            ErrorFix("Check enabled extensions", "php -m", "View currently enabled PHP modules."),
            ErrorFix(
                "Install via Homebrew",
                "brew install php",
                "Install full PHP package with common extensions.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="java_unsupported_class_version",
        category="java",
        pattern=re.compile(
            r"has been compiled by a more recent version of the Java Runtime \(class file version (\d+)"
        ),
        title="Java UnsupportedClassVersionError",
        likely_cause="Compiled Java bytecode requires a newer JRE than the currently running java version.",
        fixes=[
            ErrorFix("Check Java version", "java -version", "Inspect active JRE version."),
            ErrorFix(
                "Switch JAVA_HOME",
                "export JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.21.0.2/libexec/openjdk.jdk/Contents/Home",
                "Switch to compatible JDK.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="go_module_not_found",
        category="go",
        pattern=re.compile(r"no required module provides package"),
        title="Go Module Missing Dependency",
        likely_cause="Package dependency is not declared in go.mod.",
        fixes=[
            ErrorFix(
                "Tidy go module", "go mod tidy", "Download missing dependencies and update go.mod."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="c_compiler_clang_error",
        category="build",
        pattern=re.compile(r"clang:\s+error:\s+no such file or directory"),
        title="Clang C/C++ Compiler Error",
        likely_cause="Source file or include header does not exist.",
        fixes=[
            ErrorFix("Verify source path", "ls -la", "Check paths passed to compiler."),
        ],
    ),
    # --- Python Errors ---
    ErrorSignature(
        signature_id="py_module_not_found",
        category="python",
        pattern=re.compile(r"ModuleNotFoundError:\s+No module named ['\"]([^'\"]+)['\"]"),
        title="Python ModuleNotFoundError",
        likely_cause="The specified Python package is not installed in the active environment or virtualenv.",
        fixes=[
            ErrorFix(
                "Install missing package",
                "pip install <package>",
                "Install into active virtual environment.",
            ),
            ErrorFix(
                "Verify active Python",
                "which python3 && python3 -m pip list",
                "Ensure virtual environment is activated.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_import_error",
        category="python",
        pattern=re.compile(r"ImportError:\s+cannot import name ['\"]([^'\"]+)['\"]"),
        title="Python ImportError",
        likely_cause="Circular import, name collision with local file, or outdated library version.",
        fixes=[
            ErrorFix(
                "Check local filename collisions",
                "ls -la *.py",
                "Ensure your script isn't named the same as an imported package.",
            ),
            ErrorFix(
                "Upgrade library",
                "pip install --upgrade <package>",
                "Upgrade the library to a version containing the symbol.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_syntax_error",
        category="python",
        pattern=re.compile(r"SyntaxError:\s+(.+)"),
        title="Python SyntaxError",
        likely_cause="Invalid Python syntax (e.g. missing colon, mismatched brackets, or incompatible Python version).",
        fixes=[
            ErrorFix(
                "Check Python version",
                "python3 --version",
                "Ensure your interpreter supports the syntax (e.g. match/case requires Python 3.10+).",
            ),
            ErrorFix(
                "Inspect line error",
                None,
                "Review the line indicated by the caret (^) in the traceback.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_indentation_error",
        category="python",
        pattern=re.compile(r"IndentationError:\s+(.+)"),
        title="Python IndentationError",
        likely_cause="Inconsistent use of tabs and spaces or missing indentation block.",
        fixes=[
            ErrorFix(
                "Format with Ruff",
                "ruff format <file.py>",
                "Automatically normalize indentation using Ruff.",
            ),
            ErrorFix(
                "Convert tabs to spaces", None, "Configure editor to use 4 spaces per tab stop."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_type_error",
        category="python",
        pattern=re.compile(r"TypeError:\s+(.+)"),
        title="Python TypeError",
        likely_cause="An operation or function was applied to an object of inappropriate type.",
        fixes=[
            ErrorFix(
                "Inspect types",
                None,
                "Add type annotations and run 'mypy' to locate typing mismatches.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_key_error",
        category="python",
        pattern=re.compile(r"KeyError:\s+(.+)"),
        title="Python KeyError",
        likely_cause="Dictionary key was not found in dictionary mapping.",
        fixes=[
            ErrorFix(
                "Use dict.get",
                None,
                "Use dict.get(key, default) instead of direct indexing dict[key].",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_file_not_found",
        category="python",
        pattern=re.compile(
            r"FileNotFoundError:\s+\[Errno 2\] No such file or directory:\s+['\"]([^'\"]+)['\"]"
        ),
        title="Python FileNotFoundError",
        likely_cause="The target file or directory does not exist relative to the current working directory.",
        fixes=[
            ErrorFix(
                "Verify path and working directory",
                "pwd && ls -la <path>",
                "Check relative vs absolute path resolution.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_pep668_externally_managed",
        category="python",
        pattern=re.compile(r"error:\s+externally-managed-environment", re.I),
        title="PEP 668 Externally Managed Environment",
        likely_cause="On macOS (Homebrew or Python 3.12+), global pip installs are restricted to prevent corrupting system/brew packages.",
        fixes=[
            ErrorFix(
                "Create a virtual environment",
                "python3 -m venv .venv && source .venv/bin/activate",
                "Always install packages inside an isolated venv.",
            ),
            ErrorFix(
                "Install CLI tool via pipx",
                "pipx install <package>",
                "Use pipx for standalone global command-line tools.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_pip_resolver_conflict",
        category="python",
        pattern=re.compile(r"ResolutionImpossible:\s+for package", re.I),
        title="pip Dependency Resolution Conflict",
        likely_cause="Installed or requested packages have mutually incompatible version constraints.",
        fixes=[
            ErrorFix(
                "Inspect dependency tree",
                "pip install pipdeptree && pipdeptree",
                "Find which packages require conflicting versions.",
            ),
            ErrorFix(
                "Relax pinned requirements",
                None,
                "Remove overly restrictive == version pins in requirements.txt.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="py_ssl_cert_verify_failed",
        category="python",
        pattern=re.compile(r"CERTIFICATE_VERIFY_FAILED", re.I),
        title="Python SSL Certificate Verification Failed",
        likely_cause="Python on macOS is missing system root certificates.",
        fixes=[
            ErrorFix(
                "Install certificates (Python.org)",
                "/Applications/Python*/Install\\ Certificates.command",
                "Run bundled certificate installer script.",
            ),
            ErrorFix(
                "Install certifi",
                "pip install --upgrade certifi",
                "Update the CA certificate bundle.",
            ),
        ],
    ),
    # --- Node / npm / yarn / pnpm Errors ---
    ErrorSignature(
        signature_id="node_module_not_found",
        category="node",
        pattern=re.compile(r"Error:\s+Cannot find module\s+['\"]([^'\"]+)['\"]"),
        title="Node.js Cannot Find Module",
        likely_cause="Node.js cannot find package in local node_modules directory.",
        fixes=[
            ErrorFix(
                "Install dependencies",
                "npm install",
                "Install dependencies declared in package.json.",
            ),
            ErrorFix(
                "Check file path",
                None,
                "Ensure relative path './filename' has correct extension and case.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_eresolve",
        category="node",
        pattern=re.compile(r"npm ERR!\s+code\s+ERESOLVE", re.I),
        title="npm ERESOLVE Dependency Conflict",
        likely_cause="Conflicting peer dependency requirements in package-lock.json.",
        fixes=[
            ErrorFix(
                "Install with legacy peer deps",
                "npm install --legacy-peer-deps",
                "Bypass strict peer dependency resolution.",
            ),
            ErrorFix(
                "Run clean install",
                "rm -rf node_modules package-lock.json && npm install",
                "Recompute lockfile.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_enoent_package_json",
        category="node",
        pattern=re.compile(
            r"npm ERR!\s+enoent\s+ENOENT: no such file or directory, open\s+.*package\.json"
        ),
        title="npm Missing package.json",
        likely_cause="npm command was executed in a directory that is not a Node.js project root.",
        fixes=[
            ErrorFix(
                "Check directory", "pwd && ls -la", "Navigate to directory containing package.json."
            ),
            ErrorFix(
                "Initialize project",
                "npm init -y",
                "Create a new package.json if starting a new project.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="node_eaddrinuse",
        category="node",
        pattern=re.compile(
            r"Error:\s+listen EADDRINUSE:?\s+(?:address already in use\s+)?(?:::|0\.0\.0\.0|127\.0\.0\.1)?:?(\d+)?"
        ),
        title="Network Port EADDRINUSE Conflict",
        likely_cause="Another server or background process is already listening on the requested port.",
        fixes=[
            ErrorFix(
                "Find occupying process",
                "lsof -i :<port>",
                "Identify which process PID is holding the port.",
            ),
            ErrorFix(
                "Kill occupying process",
                "lsof -ti :<port> | xargs kill -9",
                "Terminate the conflicting server.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="node_heap_out_of_memory",
        category="node",
        pattern=re.compile(r"JavaScript heap out of memory", re.I),
        title="Node.js V8 Heap Out of Memory",
        likely_cause="Build process or script exceeded the default V8 memory allocation limit (~2-4 GB).",
        fixes=[
            ErrorFix(
                "Increase Node memory limit",
                "export NODE_OPTIONS='--max-old-space-size=8192'",
                "Allocate 8 GB of heap memory to Node.js.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="npm_engine_mismatch",
        category="node",
        pattern=re.compile(r"npm ERR!\s+code\s+EBADENGINE", re.I),
        title="npm EBADENGINE Unsupported Runtime",
        likely_cause="Installed Node.js or npm version does not satisfy the 'engines' constraint in package.json.",
        fixes=[
            ErrorFix(
                "Switch Node version with nvm/fnm",
                "nvm use || fnm use",
                "Switch to compatible Node version specified in .nvmrc.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="node_gyp_failure",
        category="node",
        pattern=re.compile(r"gyp\s+ERR!\s+(?:build error|stack Error:)", re.I),
        title="node-gyp Native Compilation Failure",
        likely_cause="Native C/C++ module failed to compile; missing Xcode Command Line Tools or Python.",
        fixes=[
            ErrorFix(
                "Install Xcode Command Line Tools",
                "xcode-select --install",
                "Provide clang and header files.",
            ),
        ],
    ),
    # --- Git Errors ---
    ErrorSignature(
        signature_id="git_not_a_repo",
        category="git",
        pattern=re.compile(
            r"fatal:\s+not a git repository \(or any of the parent directories\):\s+\.git"
        ),
        title="Not a Git Repository",
        likely_cause="The current directory is not tracked by Git.",
        fixes=[
            ErrorFix("Check directory", "pwd", "Verify you are in the correct repository root."),
            ErrorFix(
                "Initialize git repository", "git init", "Initialize a new Git repository here."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_merge_conflict",
        category="git",
        pattern=re.compile(r"CONFLICT \(content\):\s+Merge conflict in\s+(.+)"),
        title="Git Merge Conflict",
        likely_cause="Both branches modified the same lines in the listed file.",
        fixes=[
            ErrorFix("Inspect conflict status", "git status", "View list of unmerged paths."),
            ErrorFix(
                "Abort merge", "git merge --abort", "Cancel merge and return to previous state."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_index_lock",
        category="git",
        pattern=re.compile(r"fatal:\s+Unable to create '.*\.git/index\.lock':\s+File exists"),
        title="Git Index Lock File Exists",
        likely_cause="Another git process is running, or a previous git command crashed leaving index.lock behind.",
        fixes=[
            ErrorFix(
                "Check running git processes",
                "ps aux | grep git",
                "Ensure no active git process is running.",
            ),
            ErrorFix(
                "Remove stale lock file",
                "rm -f .git/index.lock",
                "Delete lock if no git process is active.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_detached_head",
        category="git",
        pattern=re.compile(r"You are in 'detached HEAD' state", re.I),
        title="Git Detached HEAD State",
        likely_cause="You checked out a specific commit hash or tag rather than a named branch.",
        fixes=[
            ErrorFix(
                "Create new branch from commit",
                "git switch -c <new-branch-name>",
                "Retain your commits on a new branch.",
            ),
            ErrorFix(
                "Return to main branch", "git switch main", "Return to your primary working branch."
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_non_fast_forward",
        category="git",
        pattern=re.compile(r"Updates were rejected because the remote contains work", re.I),
        title="Git Push Rejected (Non-Fast-Forward)",
        likely_cause="Remote branch has commits that you do not have locally.",
        fixes=[
            ErrorFix(
                "Pull and rebase",
                "git pull --rebase origin <branch>",
                "Incorporate remote commits before pushing.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_unrelated_histories",
        category="git",
        pattern=re.compile(r"fatal:\s+refusing to merge unrelated histories"),
        title="Git Refusing to Merge Unrelated Histories",
        likely_cause="Merging two repositories that were initialized independently without common root commit.",
        fixes=[
            ErrorFix(
                "Allow unrelated histories",
                "git pull origin <branch> --allow-unrelated-histories",
                "Force merge of distinct git histories.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="git_ssh_permission_denied",
        category="git",
        pattern=re.compile(r"Permission denied \(publickey\)", re.I),
        title="SSH Permission Denied (Publickey)",
        likely_cause="SSH key is not loaded in ssh-agent or public key is not registered on remote host (GitHub/GitLab).",
        fixes=[
            ErrorFix(
                "Check loaded SSH keys", "ssh-add -l", "List keys currently loaded in ssh-agent."
            ),
            ErrorFix(
                "Add SSH key to agent",
                "ssh-add ~/.ssh/id_ed25519",
                "Load your private key into the agent.",
            ),
            ErrorFix(
                "Test GitHub connection",
                "ssh -T git@github.com",
                "Verify SSH handshake with GitHub.",
            ),
        ],
    ),
    # --- macOS Permissions & System Errors ---
    ErrorSignature(
        signature_id="macos_operation_not_permitted",
        category="macos",
        pattern=re.compile(r"Operation not permitted", re.I),
        title="macOS TCC Privacy Restriction",
        likely_cause="macOS Transparency, Consent, and Control (TCC) blocked access to protected user folder (Desktop, Documents, Downloads).",
        fixes=[
            ErrorFix(
                "Grant Full Disk Access",
                None,
                "Open System Settings -> Privacy & Security -> Full Disk Access and enable your terminal app.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="macos_xcrun_invalid_active_developer_path",
        category="macos",
        pattern=re.compile(r"xcrun:\s+error:\s+invalid active developer path\s+\((.+)\)", re.I),
        title="macOS Missing Xcode Command Line Tools",
        likely_cause="Xcode Command Line Tools are missing or path was broken by a macOS system update.",
        fixes=[
            ErrorFix(
                "Reinstall Command Line Tools",
                "xcode-select --install",
                "Triggers macOS installer prompt for developer tools.",
            ),
            ErrorFix(
                "Reset developer path",
                "sudo xcode-select --reset",
                "Restores default developer tools path.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="macos_gatekeeper_unverified",
        category="macos",
        pattern=re.compile(r"cannot be opened because the developer cannot be verified", re.I),
        title="macOS Gatekeeper Quarantine Restriction",
        likely_cause="Downloaded binary or app has the com.apple.quarantine extended attribute set.",
        fixes=[
            ErrorFix(
                "Remove quarantine attribute",
                "xattr -d com.apple.quarantine <app_or_binary>",
                "Remove Gatekeeper quarantine flag for trusted tools.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="macos_rosetta_bad_cpu_type",
        category="macos",
        pattern=re.compile(r"bad CPU type in executable", re.I),
        title="macOS Bad CPU Type (Rosetta 2 Required)",
        likely_cause="Attempting to run an x86_64 Intel binary on Apple Silicon without Rosetta 2 installed.",
        fixes=[
            ErrorFix(
                "Install Rosetta 2",
                "softwareupdate --install-rosetta --agree-to-license",
                "Install Apple Silicon x86_64 translation layer.",
            ),
        ],
    ),
    # --- Shell & Core OS Errors ---
    ErrorSignature(
        signature_id="shell_command_not_found",
        category="shell",
        pattern=re.compile(r"(?:zsh|bash|sh):\s+command not found:\s+(.+)"),
        title="Shell Command Not Found",
        likely_cause="Executable is not installed or its directory is not included in PATH.",
        fixes=[
            ErrorFix("Check PATH", "echo $PATH", "Verify directory is in PATH."),
            ErrorFix(
                "Install via Homebrew",
                "brew install <tool>",
                "Install the missing command using Homebrew.",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="shell_no_matches_found",
        category="shell",
        pattern=re.compile(r"zsh:\s+no matches found:\s+(.+)"),
        title="zsh Glob Pattern No Matches Found",
        likely_cause="zsh tried to expand an unquoted wildcard glob that matched no files (common in curl URLs or git commands).",
        fixes=[
            ErrorFix(
                "Quote the argument",
                None,
                "Wrap the argument in single quotes (e.g. 'HEAD^' or 'https://api?foo=1&bar=2').",
            ),
        ],
    ),
    ErrorSignature(
        signature_id="shell_permission_denied",
        category="shell",
        pattern=re.compile(r"(?:zsh|bash|sh):\s+permission denied:\s+(.+)"),
        title="Shell Script Permission Denied",
        likely_cause="Target file lacks execute (+x) permissions or user lacks access rights.",
        fixes=[
            ErrorFix(
                "Add execute permission", "chmod +x <file>", "Grant execute permission to script."
            ),
        ],
    ),
    # --- Package Managers & Docker ---
    ErrorSignature(
        signature_id="brew_no_available_formula",
        category="brew",
        pattern=re.compile(r"Error:\s+No available formula with the name\s+['\"]([^'\"]+)['\"]"),
        title="Homebrew Formula Not Found",
        likely_cause="Formula name is misspelled, deprecated, or lives in a third-party tap.",
        fixes=[
            ErrorFix("Search Homebrew", "brew search <name>", "Find correct package or cask name."),
        ],
    ),
    ErrorSignature(
        signature_id="docker_daemon_not_running",
        category="docker",
        pattern=re.compile(
            r"Cannot connect to the Docker daemon at .+ Is the docker daemon running\?", re.I
        ),
        title="Docker Daemon Not Running",
        likely_cause="Docker Desktop, Colima, or OrbStack hypervisor is not started.",
        fixes=[
            ErrorFix(
                "Start Docker Desktop", "open -a Docker", "Launch Docker desktop application."
            ),
            ErrorFix("Start Colima", "colima start", "Start Colima background VM if using Colima."),
        ],
    ),
    ErrorSignature(
        signature_id="docker_port_allocated",
        category="docker",
        pattern=re.compile(r"Bind for .+ failed: port is already allocated", re.I),
        title="Docker Port Conflict",
        likely_cause="Another container or host service is already bound to the requested host port.",
        fixes=[
            ErrorFix("Check Docker containers", "docker ps", "Find containers occupying the port."),
            ErrorFix(
                "Check host listening ports",
                "lsof -i :<port>",
                "Identify host process using the port.",
            ),
        ],
    ),
]


def match_error(error_text: str) -> list[ErrorSignature]:
    """Scan error text and return all matched error signatures."""
    matched: list[ErrorSignature] = []
    for sig in ERROR_SIGNATURES:
        if sig.pattern.search(error_text):
            matched.append(sig)
    return matched
