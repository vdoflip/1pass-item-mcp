"""Configuration: the explicit allowlist of 1Password items and how each may be used."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 CI only
    import tomli as tomllib

CONFIG_ENV = "ONEPASS_ITEM_MCP_CONFIG"

ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
# op://vault/item/field or op://vault/item/section/field, optional ?attribute=otp|totp
REF_RE = re.compile(r"^op://[^/?]+/[^/?]+(?:/[^/?]+)?/[^/?]+(?:\?attribute=(?:otp|totp))?$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
COMMAND_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")

# Environment variables a secret must never be placed in: they change how
# programs load code, find binaries or run helpers, or belong to 1Password.
FORBIDDEN_ENV = frozenset(
    {
        "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "IFS", "ENV", "BASH_ENV",
        "CDPATH", "PS4", "PROMPT_COMMAND", "TMPDIR", "XDG_CONFIG_HOME",
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONINSPECT",
        "NODE_OPTIONS", "NODE_PATH", "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH",
        "GIT_ASKPASS", "SSH_ASKPASS", "EDITOR", "VISUAL", "PAGER", "GIT_PAGER", "BROWSER",
        "LESSOPEN", "LESSCLOSE", "MANPAGER",
    }
)  # fmt: skip
FORBIDDEN_ENV_PREFIXES = ("LD_", "DYLD_", "OP_", "MALLOC_", "GCONV_", "GIT_CONFIG_")

# Programs that can evaluate arbitrary code, dump their environment, read arbitrary
# files (/proc/self/environ), re-encode output or send arbitrary data anywhere. These
# can never be allowlisted: with them, "the agent never sees the secret" is meaningless.
DENIED_EXECUTABLES = frozenset(
    {
        "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "ash", "nu", "elvish",
        "busybox", "toybox", "env", "printenv", "export", "xargs", "sudo", "doas", "su",
        "pkexec", "runuser", "nohup", "setsid", "time", "timeout", "nice", "ionice", "stdbuf",
        "chroot", "unshare", "nsenter", "script", "expect", "tmux", "screen", "watch",
        "strace", "ltrace", "gdb", "lldb", "perf", "valgrind", "dtrace", "dtruss",
        "python", "pypy", "node", "nodejs", "deno", "bun", "perl", "ruby", "irb", "php",
        "lua", "luajit", "tclsh", "wish", "r", "rscript", "julia", "osascript", "powershell",
        "pwsh", "cmd", "awk", "gawk", "mawk", "nawk", "sed", "find", "vim", "vi", "nvim",
        "emacs", "nano", "less", "more", "man", "ssh-agent", "op", "1password", "1pass-item-mcp",
        # File readers, filters and encoders: could read /proc/self/environ or re-encode
        # output past the masking.
        "cat", "tac", "nl", "od", "xxd", "hexdump", "base64", "base32", "basenc", "uuencode",
        "strings", "head", "tail", "cut", "tr", "dd", "cp", "mv", "tee", "rev", "fold", "paste",
        "sort", "uniq", "column", "jq", "yq", "gojq", "grep", "egrep", "fgrep", "rg", "ag",
        "diff", "cmp", "comm", "split", "openssl", "gpg", "age", "zip", "tar", "gzip", "xz",
        "zstd", "bzip2", "curl", "wget", "nc", "ncat", "socat", "telnet", "scp", "rsync",
    }
)  # fmt: skip
DENIED_EXECUTABLE_RE = re.compile(r"^(python|pypy|ruby|perl|php|node|lua|pip|java)[0-9.]*$")

# Programs that run code the agent can edit (build scripts, package lifecycle
# scripts, git hooks, Makefiles, IaC local-exec, ...). Allowed only when the
# item sets allow_project_code = true.
PROJECT_CODE_EXECUTABLES = frozenset(
    {
        "make", "gmake", "cmake", "ninja", "just", "task", "npm", "npx", "yarn", "pnpm",
        "corepack", "pip", "pip3", "pipx", "uv", "uvx", "poetry", "pdm", "hatch", "tox", "nox",
        "cargo", "go", "mvn", "gradle", "gradlew", "sbt", "dotnet", "bundle", "rake",
        "composer", "mix", "git", "docker", "podman", "docker-compose", "terraform", "tofu",
        "terragrunt", "pulumi", "ansible", "ansible-playbook", "helm", "kubectl", "pytest",
        "jest", "vitest", "mocha",
    }
)  # fmt: skip


class ConfigError(Exception):
    """The configuration file is missing, unsafe or invalid."""


def executable_denied(name: str) -> bool:
    base = os.path.basename(name).lower()
    return base in DENIED_EXECUTABLES or bool(DENIED_EXECUTABLE_RE.match(base))


def executable_runs_project_code(name: str) -> bool:
    return os.path.basename(name).lower() in PROJECT_CODE_EXECUTABLES


class OnePasswordSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: Literal["desktop", "service-account", "cli"] = "desktop"
    account: str | None = Field(
        default=None,
        description="Desktop backend: account name or sign-in address shown in the 1Password app.",
    )
    token_env: str = Field(
        default="OP_SERVICE_ACCOUNT_TOKEN",
        description="Service-account backend: env var holding the token. Read once, then removed.",
    )
    op_path: str = Field(default="op", description="CLI backend: path or name of the op binary.")

    @model_validator(mode="after")
    def _account_for_desktop(self) -> OnePasswordSettings:
        if self.backend == "desktop" and not (self.account and self.account.strip()):
            raise ValueError("onepassword.account is required for the desktop backend")
        return self


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_timeout_seconds: int = Field(default=60, ge=1, le=3600)
    max_timeout_seconds: int = Field(default=300, ge=1, le=3600)
    max_output_bytes: int = Field(default=65536, ge=1024, le=1_048_576)
    max_items_per_call: int = Field(default=5, ge=1, le=20)

    @model_validator(mode="after")
    def _default_within_max(self) -> Limits:
        if self.default_timeout_seconds > self.max_timeout_seconds:
            raise ValueError("default_timeout_seconds must be <= max_timeout_seconds")
        return self


class AuditSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    path: str | None = None


class ItemConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref: str = Field(description="Secret reference: op://vault/item[/section]/field")
    env: str = Field(description="Environment variable the secret is injected into.")
    commands: list[str] = Field(min_length=1, description="Executables this item may be used with.")
    description: str = ""
    args_prefixes: list[list[str]] | None = Field(
        default=None,
        description="If set, the command's arguments must start with one of these sequences.",
    )
    max_uses: int | None = Field(default=None, ge=1, description="Uses allowed per server session.")
    allow_project_code: bool = Field(
        default=False,
        description="Allow commands that run agent-editable code (npm, make, git, docker, ...).",
    )

    @field_validator("ref")
    @classmethod
    def _check_ref(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v) or not REF_RE.match(v):
            raise ValueError(
                "ref must look like op://vault/item/field or op://vault/item/section/field"
            )
        return v

    @field_validator("env")
    @classmethod
    def _check_env(cls, v: str) -> str:
        if not ENV_RE.match(v):
            raise ValueError("env must be an UPPER_CASE environment variable name")
        if v in FORBIDDEN_ENV or v.startswith(FORBIDDEN_ENV_PREFIXES):
            raise ValueError(f"env {v!r} is not allowed (it controls code loading or 1Password)")
        return v

    @field_validator("commands")
    @classmethod
    def _check_commands(cls, v: list[str]) -> list[str]:
        for c in v:
            if os.path.isabs(c):
                if ".." in Path(c).parts:
                    raise ValueError(f"command path {c!r} must not contain '..'")
            elif not COMMAND_NAME_RE.match(c):
                raise ValueError(f"command {c!r} must be a plain executable name or absolute path")
            if executable_denied(c):
                raise ValueError(
                    f"command {c!r} can run arbitrary code, read files or print its "
                    "environment and is never allowed"
                )
        if len(set(v)) != len(v):
            raise ValueError("commands contains duplicates")
        return v

    @field_validator("args_prefixes")
    @classmethod
    def _check_prefixes(cls, v: list[list[str]] | None) -> list[list[str]] | None:
        if v is not None and (not v or any(not p for p in v)):
            raise ValueError("args_prefixes must be a non-empty list of non-empty lists")
        return v

    @model_validator(mode="after")
    def _project_code(self) -> ItemConfig:
        risky = [c for c in self.commands if executable_runs_project_code(c)]
        if risky and not self.allow_project_code:
            raise ValueError(
                f"command(s) {risky} can run agent-editable project code (scripts, hooks, "
                "Makefiles) that could print the secret; set allow_project_code = true "
                "only if you accept that"
            )
        return self


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    onepassword: OnePasswordSettings
    limits: Limits = Limits()
    audit: AuditSettings = AuditSettings()
    items: dict[str, ItemConfig] = Field(default_factory=dict)

    @field_validator("items")
    @classmethod
    def _check_aliases(cls, v: dict[str, ItemConfig]) -> dict[str, ItemConfig]:
        for alias in v:
            if not ALIAS_RE.match(alias):
                raise ValueError(f"item alias {alias!r} must match {ALIAS_RE.pattern}")
        return v


def default_config_path() -> Path:
    env = os.environ.get(CONFIG_ENV)
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "1pass-item-mcp" / "config.toml"


def default_state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "1pass-item-mcp"


def check_file_safety(path: Path) -> None:
    """Refuse configs that other users (or other groups) could have modified."""
    if os.name != "posix":  # pragma: no cover
        return
    for p, what in ((path, "config file"), (path.parent, "config directory")):
        st = os.stat(p)
        if st.st_uid != os.getuid():
            raise ConfigError(f"{what} {p} must be owned by the current user")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigError(f"{what} {p} must not be group- or world-writable (chmod go-w)")


def parse_config(text: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML: {e}") from None
    try:
        return Config.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"invalid configuration:\n{e}") from None


def load_config(path: Path) -> Config:
    if not path.is_file():
        raise ConfigError(f"config file not found: {path} (create one with: 1pass-item-mcp init)")
    check_file_safety(path)
    return parse_config(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class ResolvedCommand:
    """A configured command pinned to a concrete binary at startup."""

    entry: str
    path: str
    sha256: str
    user_writable: bool


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_command(entry: str, search_path: str | None = None) -> ResolvedCommand:
    """Find the binary for a configured command and pin it by real path and hash."""
    found = entry if os.path.isabs(entry) else shutil.which(entry, path=search_path)
    if not found or not os.path.isfile(found) or not os.access(found, os.X_OK):
        raise ConfigError(f"command {entry!r} not found or not executable")
    real = os.path.realpath(found)
    if executable_denied(real):
        raise ConfigError(f"command {entry!r} resolves to {real}, which is never allowed")
    writable = os.access(real, os.W_OK) or os.access(os.path.dirname(real), os.W_OK)
    return ResolvedCommand(entry=entry, path=real, sha256=file_sha256(real), user_writable=writable)


def resolve_all_commands(
    cfg: Config, search_path: str | None = None
) -> tuple[dict[str, ResolvedCommand], dict[str, str]]:
    """Resolve every configured command. Returns (resolved, errors) keyed by entry."""
    resolved: dict[str, ResolvedCommand] = {}
    errors: dict[str, str] = {}
    for item in cfg.items.values():
        for entry in item.commands:
            if entry in resolved or entry in errors:
                continue
            try:
                resolved[entry] = resolve_command(entry, search_path)
            except ConfigError as e:
                errors[entry] = str(e)
    return resolved, errors


EXAMPLE_CONFIG = """\
# 1pass-item-mcp configuration: the ONLY 1Password items an agent can ask for.
# Keep this file private (chmod 600). The server reads it once at startup.

[onepassword]
backend = "desktop"            # desktop | service-account | cli
account = "my.1password.com"   # desktop: account name or sign-in address shown in the 1Password app

[limits]
default_timeout_seconds = 60
max_timeout_seconds = 300
max_output_bytes = 65536
max_items_per_call = 5

[audit]
enabled = true                 # JSONL log of every request (never contains secrets)
# path = "~/.local/state/1pass-item-mcp/audit.jsonl"

# Each item: one secret, the env var it is injected into, and the only commands
# that may receive it. The agent never sees the value.
#
# [items.github]
# description = "GitHub token (read-only scopes) for the gh CLI"
# ref = "op://Development/GitHub PAT/token"
# env = "GH_TOKEN"
# commands = ["gh"]
# args_prefixes = [["api"], ["pr", "view"], ["run", "list"]]
# max_uses = 20
"""
