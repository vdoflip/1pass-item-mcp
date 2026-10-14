"""Run one allowlisted command with secrets injected into its environment."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from collections.abc import Mapping
from dataclasses import dataclass

from onepass_item_mcp.config import FORBIDDEN_ENV_PREFIXES

KILL_GRACE_SECONDS = 2.0
DRAIN_AFTER_EXIT_SECONDS = 5.0
_STRIP_FROM_CHILD_ENV_PREFIXES = (*FORBIDDEN_ENV_PREFIXES, "ONEPASS_ITEM_MCP_")


@dataclass(frozen=True)
class RunOutcome:
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


def child_environment(base: Mapping[str, str], secrets: Mapping[str, str]) -> dict[str, str]:
    """Parent env minus 1Password/loader variables, plus the injected secrets."""
    env = {k: v for k, v in base.items() if not k.startswith(_STRIP_FROM_CHILD_ENV_PREFIXES)}
    env.update(secrets)
    return env


async def _drain(stream: asyncio.StreamReader | None, limit: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        room = limit - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            truncated = True  # keep reading so the child never blocks on a full pipe
    return bytes(buf), truncated


def _kill_group(proc: asyncio.subprocess.Process, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        else:  # pragma: no cover
            proc.send_signal(sig)


async def run_command(
    path: str,
    args: list[str],
    *,
    env: Mapping[str, str],
    cwd: str | None,
    timeout: float,
    capture_limit: int,
) -> RunOutcome:
    """Execute `path args...` directly (never through a shell)."""
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        path,
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=dict(env),
        start_new_session=True,  # own process group, so a timeout kills grandchildren too
    )
    out_task = asyncio.create_task(_drain(proc.stdout, capture_limit))
    err_task = asyncio.create_task(_drain(proc.stderr, capture_limit))
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        _kill_group(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=KILL_GRACE_SECONDS)
        except asyncio.TimeoutError:
            _kill_group(proc, signal.SIGKILL)
            await proc.wait()
    finally:
        if proc.returncode is None:  # cancelled from outside
            _kill_group(proc, signal.SIGKILL)

    # Grandchildren may still hold the pipes open; don't wait on them forever.
    done, pending = await asyncio.wait({out_task, err_task}, timeout=DRAIN_AFTER_EXIT_SECONDS)
    if pending:
        _kill_group(proc, signal.SIGKILL)
        for t in pending:
            t.cancel()
    stdout, out_trunc = out_task.result() if out_task in done else (b"", True)
    stderr, err_trunc = err_task.result() if err_task in done else (b"", True)

    return RunOutcome(
        exit_code=None if timed_out else proc.returncode,
        timed_out=timed_out,
        duration_seconds=round(time.monotonic() - start, 3),
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=out_trunc,
        stderr_truncated=err_trunc,
    )
