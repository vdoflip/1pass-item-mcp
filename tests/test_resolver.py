from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from conftest import make_executable

from onepass_item_mcp.config import OnePasswordSettings
from onepass_item_mcp.resolver import (
    CliResolver,
    DesktopResolver,
    ResolveError,
    ServiceAccountResolver,
    build_resolver,
)

pytestmark = pytest.mark.anyio

FAKE_OP = """#!/bin/sh
if [ "$1" = read ] && [ "$2" = --no-newline ]; then
  case "$3" in
    op://V/ok/f) printf 'cli-secret-value' ;;
    *) echo "[ERROR] could not read secret: item not found" >&2; exit 1 ;;
  esac
else
  exit 64
fi
"""


@pytest.fixture
def fake_sdk(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"auths": [], "fail": None}

    class DesktopAuth:
        def __init__(self, account_name: str) -> None:
            self.account_name = account_name

    class Secrets:
        async def resolve(self, ref: str) -> str:
            if state["fail"]:
                raise RuntimeError(state["fail"])
            return f"value-of:{ref}"

    class Client:
        secrets: Secrets

        @classmethod
        async def authenticate(
            cls, auth: Any, integration_name: str, integration_version: str
        ) -> Client:
            state["auths"].append((auth, integration_name, integration_version))
            c = cls()
            c.secrets = Secrets()
            return c

    mod = types.ModuleType("onepassword")
    mod.Client = Client  # type: ignore[attr-defined]
    mod.DesktopAuth = DesktopAuth  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "onepassword", mod)
    return state


async def test_cli_resolver(tmp_path: Path) -> None:
    op = make_executable(tmp_path, "op", FAKE_OP)
    r = CliResolver(str(op))
    assert await r.resolve("op://V/ok/f") == "cli-secret-value"
    with pytest.raises(ResolveError, match="item not found"):
        await r.resolve("op://V/missing/f")


async def test_cli_resolver_missing_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ResolveError, match="not found"):
        CliResolver("op")


async def test_desktop_resolver_authenticates_once(fake_sdk: dict[str, Any]) -> None:
    r = DesktopResolver("acme.1password.com")
    assert await r.resolve("op://V/I/f") == "value-of:op://V/I/f"
    assert await r.resolve("op://V/J/f") == "value-of:op://V/J/f"
    assert len(fake_sdk["auths"]) == 1
    auth, name, _version = fake_sdk["auths"][0]
    assert auth.account_name == "acme.1password.com"
    assert name == "1pass-item-mcp"


async def test_desktop_resolver_error_is_sanitised_and_resets(fake_sdk: dict[str, Any]) -> None:
    r = DesktopResolver("acme")
    fake_sdk["fail"] = "authorization denied by user\nsecond line with details"
    with pytest.raises(ResolveError) as exc:
        await r.resolve("op://V/I/f")
    assert str(exc.value) == "1Password desktop app: authorization denied by user"
    fake_sdk["fail"] = None
    assert await r.resolve("op://V/I/f") == "value-of:op://V/I/f"
    assert len(fake_sdk["auths"]) == 2  # re-authenticated after the failure


async def test_service_account_resolver(fake_sdk: dict[str, Any]) -> None:
    r = ServiceAccountResolver("ops_token")
    assert await r.resolve("op://V/I/f") == "value-of:op://V/I/f"
    assert fake_sdk["auths"][0][0] == "ops_token"
    fake_sdk["fail"] = "rate limited"
    with pytest.raises(ResolveError, match="service account: rate limited"):
        await r.resolve("op://V/I/f")


def test_build_resolver_desktop() -> None:
    s = OnePasswordSettings(backend="desktop", account="acme")
    assert isinstance(build_resolver(s), DesktopResolver)


def test_build_resolver_service_account_pops_token() -> None:
    env = {"OP_SERVICE_ACCOUNT_TOKEN": "ops_xyz", "OTHER": "1"}
    r = build_resolver(OnePasswordSettings(backend="service-account"), env)
    assert isinstance(r, ServiceAccountResolver)
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in env  # never inherited by child processes


def test_build_resolver_service_account_requires_token() -> None:
    with pytest.raises(ResolveError, match="OP_SERVICE_ACCOUNT_TOKEN"):
        build_resolver(OnePasswordSettings(backend="service-account"), {})


def test_build_resolver_cli(tmp_path: Path) -> None:
    op = make_executable(tmp_path, "op", FAKE_OP)
    r = build_resolver(OnePasswordSettings(backend="cli", op_path=str(op)))
    assert isinstance(r, CliResolver)
