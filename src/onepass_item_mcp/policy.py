"""Decide whether a request may run. Everything here happens before 1Password is contacted."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass

from onepass_item_mcp.config import Config, ItemConfig, ResolvedCommand, file_sha256

MAX_ARGS = 256
MAX_ARG_LENGTH = 8192


class PolicyError(Exception):
    """The request is outside what the configuration allows."""


@dataclass(frozen=True)
class Plan:
    aliases: tuple[str, ...]
    items: tuple[ItemConfig, ...]
    command: ResolvedCommand
    args: tuple[str, ...]
    cwd: str | None
    timeout: float


class Policy:
    def __init__(self, cfg: Config, commands: dict[str, ResolvedCommand]) -> None:
        self.cfg = cfg
        self.commands = commands
        self.uses: Counter[str] = Counter()

    def remaining_uses(self, alias: str) -> int | None:
        limit = self.cfg.items[alias].max_uses
        return None if limit is None else max(0, limit - self.uses[alias])

    def record_use(self, aliases: tuple[str, ...]) -> None:
        self.uses.update(aliases)

    def check(
        self,
        aliases: list[str],
        command: list[str],
        cwd: str | None = None,
        timeout_seconds: int | None = None,
    ) -> Plan:
        limits = self.cfg.limits

        if not aliases:
            raise PolicyError("request at least one item")
        if len(aliases) > limits.max_items_per_call:
            raise PolicyError(f"at most {limits.max_items_per_call} items per call")
        if len(set(aliases)) != len(aliases):
            raise PolicyError("duplicate items in request")
        unknown = [a for a in aliases if a not in self.cfg.items]
        if unknown:
            known = ", ".join(sorted(self.cfg.items)) or "(none configured)"
            raise PolicyError(f"unknown item(s) {unknown}; allowlisted items: {known}")
        items = tuple(self.cfg.items[a] for a in aliases)

        for alias in aliases:
            if self.remaining_uses(alias) == 0:
                raise PolicyError(f"item {alias!r} reached its max_uses for this session")

        envs = [i.env for i in items]
        if len(set(envs)) != len(envs):
            raise PolicyError("requested items inject into the same environment variable")

        if not command:
            raise PolicyError("command must not be empty")
        if len(command) > MAX_ARGS:
            raise PolicyError(f"command has more than {MAX_ARGS} arguments")
        for arg in command:
            if "\0" in arg or len(arg) > MAX_ARG_LENGTH:
                raise PolicyError("command arguments must not contain NUL or exceed 8192 chars")

        entry, args = command[0], command[1:]
        for alias, item in zip(aliases, items, strict=True):
            if entry not in item.commands:
                raise PolicyError(
                    f"item {alias!r} may only be used with {item.commands}, not {entry!r}"
                )
            if item.args_prefixes is not None and not any(
                args[: len(p)] == p for p in item.args_prefixes
            ):
                raise PolicyError(
                    f"item {alias!r} only allows arguments starting with {item.args_prefixes}"
                )
        resolved = self.commands.get(entry)
        if resolved is None:
            raise PolicyError(f"command {entry!r} is not installed or failed validation at startup")

        if cwd is not None:
            if not os.path.isabs(cwd) or not os.path.isdir(cwd):
                raise PolicyError("cwd must be an existing absolute directory")
            cwd = os.path.realpath(cwd)

        timeout = limits.default_timeout_seconds if timeout_seconds is None else timeout_seconds
        if not 1 <= timeout <= limits.max_timeout_seconds:
            raise PolicyError(f"timeout_seconds must be between 1 and {limits.max_timeout_seconds}")

        return Plan(tuple(aliases), items, resolved, tuple(args), cwd, float(timeout))

    @staticmethod
    def verify_binary(cmd: ResolvedCommand) -> None:
        """Refuse to run a binary that changed since startup (e.g. replaced by the agent)."""
        try:
            current = file_sha256(cmd.path)
        except OSError:
            current = ""
        if current != cmd.sha256:
            raise PolicyError(
                f"{cmd.path} changed since the server started; refusing to run it. "
                "Restart the MCP server if the update was intended."
            )
