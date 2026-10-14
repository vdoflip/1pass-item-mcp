"""The MCP server: `list_items` (no secrets) and `run_with_items` (approved on every call)."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from onepass_item_mcp import NAME, __version__
from onepass_item_mcp.audit import AuditLog
from onepass_item_mcp.config import Config, ResolvedCommand
from onepass_item_mcp.policy import Policy, PolicyError
from onepass_item_mcp.redact import Redactor, SecretTooShortError
from onepass_item_mcp.resolver import ResolveError, SecretResolver
from onepass_item_mcp.runner import child_environment, run_command

log = logging.getLogger(__name__)

# Claude Code shows the permission prompt for such a tool on every call, in every
# permission mode, without a "don't ask again" option.
REQUIRES_USER_INTERACTION = "anthropic/requiresUserInteraction"

INSTRUCTIONS = """\
Use 1Password items without ever seeing their values.

1. Call list_items to see the allowlisted items, the env var each is injected into,
   and the only commands each may be used with.
2. Call run_with_items with the item aliases, the command as an argv list, and a short
   reason. The user approves every call. The command runs directly (no shell: no pipes,
   globs, $VARS, redirects or &&). The secret is in the named env var, which the
   allowlisted program reads by itself.
3. You get exit code and output; any occurrence of the secret is masked.

Never try to print, encode or exfiltrate a secret, and never try to reach 1Password
another way (op CLI, SDKs, env files). If a request is refused, tell the user why
instead of working around it. Items not listed can only be added by the user.
"""


class ItemInfo(BaseModel):
    alias: str
    description: str
    ref: str = Field(description="1Password reference (not secret).")
    env: str = Field(description="Environment variable the value is injected into.")
    commands: list[str]
    args_prefixes: list[list[str]] | None
    uses_remaining: int | None = Field(description="None means unlimited.")
    warnings: list[str]


class ItemList(BaseModel):
    items: list[ItemInfo]


class RunResult(BaseModel):
    items: list[str]
    command: list[str]
    exit_code: int | None = Field(description="None when the command timed out.")
    timed_out: bool
    duration_seconds: float
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    redactions: int = Field(description="How many secret occurrences were masked.")


def _decode_and_mask(
    raw: bytes, truncated: bool, redactor: Redactor, max_chars: int
) -> tuple[str, bool, int]:
    text, n = redactor.redact(raw.decode("utf-8", "replace"))
    if len(text) > max_chars:
        text, truncated = text[:max_chars], True
    return text, truncated, n


def build_server(
    cfg: Config,
    resolver: SecretResolver,
    commands: dict[str, ResolvedCommand],
    *,
    command_errors: Mapping[str, str] | None = None,
    audit: AuditLog | None = None,
    environ: Mapping[str, str] | None = None,
) -> MCPServer:
    policy = Policy(cfg, commands)
    audit = audit or AuditLog(None)
    command_errors = dict(command_errors or {})
    base_env = os.environ if environ is None else environ

    server = MCPServer(NAME, instructions=INSTRUCTIONS, version=__version__)

    @server.tool(
        name="list_items",
        annotations=ToolAnnotations(
            read_only_hint=True, open_world_hint=False, idempotent_hint=True
        ),
    )
    async def list_items() -> ItemList:
        """List the allowlisted 1Password items and how each may be used. Returns no secrets."""
        out = []
        for alias, item in sorted(cfg.items.items()):
            warnings = []
            for c in item.commands:
                if c in command_errors:
                    warnings.append(command_errors[c])
                elif commands[c].user_writable:
                    warnings.append(f"{commands[c].path} is writable by the current user")
            out.append(
                ItemInfo(
                    alias=alias,
                    description=item.description,
                    ref=item.ref,
                    env=item.env,
                    commands=item.commands,
                    args_prefixes=item.args_prefixes,
                    uses_remaining=policy.remaining_uses(alias),
                    warnings=warnings,
                )
            )
        return ItemList(items=out)

    @server.tool(
        name="run_with_items",
        meta={REQUIRES_USER_INTERACTION: True},
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True
        ),
    )
    async def run_with_items(
        items: Annotated[
            list[str],
            Field(min_length=1, max_length=20, description="Item aliases from list_items."),
        ],
        command: Annotated[
            list[str],
            Field(
                min_length=1,
                description=(
                    'Executable and arguments as a list, e.g. ["gh", "api", "user"]. '
                    "Run directly, without a shell."
                ),
            ),
        ],
        reason: Annotated[
            str,
            Field(min_length=3, max_length=500, description="Why, shown to the user for approval."),
        ],
        cwd: Annotated[
            str | None, Field(description="Absolute working directory (optional).")
        ] = None,
        timeout_seconds: Annotated[
            int | None, Field(description="Timeout in seconds (optional).")
        ] = None,
    ) -> RunResult:
        """Run ONE allowlisted command with the given 1Password items injected as environment
        variables. The user approves every call. Output is returned with secrets masked;
        the secret values themselves are never returned."""
        request = {"items": items, "command": command, "reason": reason, "cwd": cwd}
        try:
            plan = policy.check(items, command, cwd, timeout_seconds)
            policy.verify_binary(plan.command)
        except PolicyError as e:
            audit.write("refused", **request, error=str(e))
            raise ToolError(f"refused: {e}") from None

        refs = [i.ref for i in plan.items]
        redactor = Redactor()
        secrets: dict[str, str] = {}
        try:
            for alias, item in zip(plan.aliases, plan.items, strict=True):
                value = await resolver.resolve(item.ref)
                redactor.add(alias, value)
                secrets[item.env] = value
        except (ResolveError, SecretTooShortError) as e:
            secrets.clear()
            audit.write("error", **request, refs=refs, error=str(e))
            raise ToolError(str(e)) from None

        policy.record_use(plan.aliases)
        max_chars = cfg.limits.max_output_bytes
        capture = max_chars + 2 * redactor.max_variant_length + 1024
        try:
            outcome = await run_command(
                plan.command.path,
                list(plan.args),
                env=child_environment(base_env, secrets),
                cwd=plan.cwd,
                timeout=plan.timeout,
                capture_limit=capture,
            )
        except OSError as e:
            audit.write("error", **request, refs=refs, error=f"could not start command: {e}")
            raise ToolError(f"could not start {plan.command.path}: {e.strerror}") from None
        finally:
            secrets.clear()

        stdout, out_trunc, n_out = _decode_and_mask(
            outcome.stdout, outcome.stdout_truncated, redactor, max_chars
        )
        stderr, err_trunc, n_err = _decode_and_mask(
            outcome.stderr, outcome.stderr_truncated, redactor, max_chars
        )
        result = RunResult(
            items=list(plan.aliases),
            command=[plan.command.entry, *plan.args],
            exit_code=outcome.exit_code,
            timed_out=outcome.timed_out,
            duration_seconds=outcome.duration_seconds,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=out_trunc,
            stderr_truncated=err_trunc,
            redactions=n_out + n_err,
        )
        audit.write(
            "run",
            **request,
            refs=refs,
            binary=plan.command.path,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            duration_seconds=result.duration_seconds,
            redactions=result.redactions,
        )
        if result.redactions:
            log.warning(
                "masked %d secret occurrence(s) in output of %s", result.redactions, command
            )
        return result

    return server
