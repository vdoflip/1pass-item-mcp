"""Fetch secret values from 1Password. Values only ever flow into child process environments."""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import MutableMapping
from typing import TYPE_CHECKING, Any, Protocol

import anyio

from onepass_item_mcp import NAME, __version__

if TYPE_CHECKING:
    from onepass_item_mcp.config import OnePasswordSettings

OP_READ_TIMEOUT_SECONDS = 180.0  # long enough for a human to approve the 1Password prompt


class ResolveError(Exception):
    """1Password could not provide the secret. Messages never contain secret values."""


class SecretResolver(Protocol):
    async def resolve(self, ref: str) -> str: ...


class DesktopResolver:
    """Uses the 1Password desktop app (SDK desktop integration).

    The app shows its own approval prompt naming this process. Authorization is per
    process and expires after 10 minutes of inactivity or when 1Password locks.
    The SDK call blocks while the prompt is open, so it runs in a worker thread.
    """

    def __init__(self, account: str) -> None:
        self._account = account
        self._client: Any = None
        self._lock = anyio.Lock()

    async def resolve(self, ref: str) -> str:
        async with self._lock:
            try:
                return await anyio.to_thread.run_sync(self._resolve_blocking, ref)
            except ResolveError:
                raise
            except Exception as e:
                self._client = None
                raise ResolveError(f"1Password desktop app: {_safe_message(e)}") from None

    def _resolve_blocking(self, ref: str) -> str:
        return asyncio.run(self._resolve_async(ref))

    async def _resolve_async(self, ref: str) -> str:
        from onepassword import Client, DesktopAuth  # noqa: PLC0415 (optional native SDK)

        if self._client is None:
            self._client = await Client.authenticate(
                auth=DesktopAuth(self._account),
                integration_name=NAME,
                integration_version=__version__,
            )
        value = await self._client.secrets.resolve(ref)
        return str(value)


class ServiceAccountResolver:
    """Uses a 1Password service account token (scope it to a dedicated vault)."""

    def __init__(self, token: str) -> None:
        self._token = token
        self._client: Any = None
        self._lock = anyio.Lock()

    async def resolve(self, ref: str) -> str:
        from onepassword import Client  # noqa: PLC0415 (optional native SDK)

        async with self._lock:
            try:
                if self._client is None:
                    self._client = await Client.authenticate(
                        auth=self._token, integration_name=NAME, integration_version=__version__
                    )
                return str(await self._client.secrets.resolve(ref))
            except Exception as e:
                self._client = None
                raise ResolveError(f"1Password service account: {_safe_message(e)}") from None


class CliResolver:
    """Uses the `op` CLI (`op read`). Useful where the SDK desktop integration is unavailable."""

    def __init__(self, op_path: str = "op") -> None:
        found = op_path if os.path.isabs(op_path) else shutil.which(op_path)
        if not found:
            raise ResolveError(f"1Password CLI {op_path!r} not found")
        self._op = found
        self._lock = anyio.Lock()

    async def resolve(self, ref: str) -> str:
        async with self._lock:
            proc = await asyncio.create_subprocess_exec(
                self._op,
                "read",
                "--no-newline",
                ref,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), OP_READ_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise ResolveError(
                    "op read timed out (was the 1Password prompt approved?)"
                ) from None
            if proc.returncode != 0:
                msg = err.decode("utf-8", "replace").strip().splitlines()
                raise ResolveError(f"op read failed: {msg[-1] if msg else proc.returncode}")
            return out.decode("utf-8")


def _safe_message(e: BaseException) -> str:
    msg = str(e).strip().splitlines()
    return (msg[0] if msg else type(e).__name__)[:300]


def build_resolver(
    settings: OnePasswordSettings, environ: MutableMapping[str, str] | None = None
) -> SecretResolver:
    """Create the configured resolver. A service-account token is removed from the environment."""
    env = os.environ if environ is None else environ
    if settings.backend == "desktop":
        if not settings.account:
            raise ResolveError("desktop backend needs onepassword.account")
        return DesktopResolver(settings.account)
    if settings.backend == "service-account":
        token = env.pop(settings.token_env, None)
        if not token:
            raise ResolveError(f"service-account backend needs ${settings.token_env} at startup")
        return ServiceAccountResolver(token)
    return CliResolver(settings.op_path)
