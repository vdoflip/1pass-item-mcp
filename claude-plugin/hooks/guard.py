#!/usr/bin/env python3
"""Claude Code PreToolUse guard shipped with the 1pass-item-mcp plugin (stdlib only).

Keeps the MCP server the only route from the agent to 1Password:
  Bash:  denies the op CLI, op:// references, 1Password SDKs/tokens, running
         1pass-item-mcp directly, and commands touching its config directory.
  Edit/Write/NotebookEdit/MultiEdit: denies writes to the config file/directory
         and to the installed plugin.

It is a guard rail against mistakes and prompt injection, not a sandbox.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys

OP_SUBCOMMANDS = {
    "account", "connect", "document", "environment", "events-api", "group", "inject",
    "item", "plugin", "read", "run", "service-account", "signin", "signout", "ssh",
    "user", "vault", "whoami", "completion", "update", "help",
}  # fmt: skip
SDK_RE = re.compile(
    r"DesktopAuth|onepassword\b|@1password/sdk|onepassword-sdk|1password-sdk|"
    r"OP_SERVICE_ACCOUNT_TOKEN|OP_SESSION_|OP_CONNECT_TOKEN|libop_sdk_ipc",
    re.IGNORECASE,
)
SPLIT_RE = re.compile(r"[\s;|&()<>`\"'{}\[\],=$]+")
SEGMENT_RE = re.compile(r"[;&|()\n`]+|\$\(")
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
LAUNCHERS = {
    "uv", "uvx", "pipx", "python", "python3", "env", "exec", "command", "nohup", "sudo",
    "doas", "timeout", "nice", "xargs", "bash", "sh", "zsh", "npx", "time",
}  # fmt: skip


def config_dir() -> str:
    env = os.environ.get("ONEPASS_ITEM_MCP_CONFIG")
    if env:
        return os.path.dirname(os.path.abspath(os.path.expanduser(env)))
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "1pass-item-mcp")


def decision(kind: str, reason: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": reason,
        }
    }


def _under(path: str, root: str) -> bool:
    if not path or not root:
        return False
    for p in {os.path.abspath(path), os.path.realpath(path)}:
        for r in {os.path.abspath(root), os.path.realpath(root)}:
            if p == r or p.startswith(r.rstrip(os.sep) + os.sep):
                return True
    return False


def is_protected_path(path: str, plugin_root: str | None) -> bool:
    path = os.path.expanduser(path)
    if _under(path, config_dir()):
        return True
    if plugin_root and _under(path, plugin_root):
        return True
    p = os.path.abspath(path)
    return (
        os.path.basename(p) == "config.toml"
        and os.path.basename(os.path.dirname(p)) == "1pass-item-mcp"
    )


def uses_op_cli(cmd: str) -> bool:
    words = [w for w in SPLIT_RE.split(cmd) if w]
    for prev, word in zip(words, words[1:]):
        if (prev == "op" or prev.endswith("/op")) and (
            word in OP_SUBCOMMANDS or word.startswith("--")
        ):
            return True
    return False


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def runs_self(cmd: str) -> bool:
    """Is 1pass-item-mcp (or `python -m onepass_item_mcp`) started by this command?"""
    for segment in SEGMENT_RE.split(cmd):
        words = [w for w in _words(segment) if not ASSIGNMENT_RE.match(w)]
        if not words:
            continue
        program = os.path.basename(words[0])
        names = {os.path.basename(w) for w in words}
        if program == "1pass-item-mcp":
            return True
        if program in LAUNCHERS or re.match(r"python[0-9.]*$", program):
            if "1pass-item-mcp" in names or "onepass_item_mcp" in names:
                return True
            if any(w.startswith("onepass_item_mcp") for w in words):
                return True
    return False


def check_bash(cmd: str, plugin_root: str | None) -> dict[str, object] | None:
    if "op://" in cmd:
        return decision(
            "deny",
            "Direct 1Password secret references are blocked. Use the 1pass-item MCP tools "
            "(list_items, run_with_items) or ask the user to run it with the ! prefix.",
        )
    if SDK_RE.search(cmd):
        return decision("deny", "Direct use of 1Password SDKs, sessions or tokens is blocked.")
    if uses_op_cli(cmd):
        return decision(
            "deny",
            "Direct use of the 1Password CLI is blocked. Use the 1pass-item MCP tools, or ask "
            "the user to run it with the ! prefix.",
        )
    if runs_self(cmd):
        return decision(
            "deny", "Running 1pass-item-mcp from the shell is blocked; use its MCP tools."
        )
    cdir = config_dir()
    home = os.path.expanduser("~")
    candidates = {cdir, cdir.replace(home, "~", 1), cdir.replace(home, "$HOME", 1)}
    if plugin_root:
        candidates.add(plugin_root)
    if any(c and c in cmd for c in candidates) or ".config/1pass-item-mcp" in cmd:
        return decision(
            "deny", "The 1pass-item-mcp configuration is managed by the user, not the agent."
        )
    if any(is_protected_path(t, plugin_root) for t in _words(cmd) if "/" in t):
        return decision(
            "deny", "The 1pass-item-mcp configuration is managed by the user, not the agent."
        )
    return None


def evaluate(payload: dict[str, object], plugin_root: str | None) -> dict[str, object] | None:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    if tool == "Bash":
        return check_bash(str(tool_input.get("command") or ""), plugin_root)
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if path and is_protected_path(path, plugin_root):
            return decision(
                "deny",
                "The 1pass-item-mcp allowlist and plugin are read-only for the agent; "
                "the user edits them.",
            )
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("1pass-item-mcp guard: unreadable hook input", file=sys.stderr)
        return 2  # fail closed
    result = evaluate(payload, os.environ.get("CLAUDE_PLUGIN_ROOT"))
    if result is not None:
        json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
