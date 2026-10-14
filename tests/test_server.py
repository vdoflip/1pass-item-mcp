from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import SECRET, FakeResolver
from mcp import Client

from onepass_item_mcp.audit import AuditLog
from onepass_item_mcp.config import Config, resolve_all_commands
from onepass_item_mcp.resolver import ResolveError
from onepass_item_mcp.server import REQUIRES_USER_INTERACTION, build_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


def make_server(config: Config, resolver: Any, audit_path: Path | None = None, **kw: Any) -> Any:
    commands, errors = resolve_all_commands(config)
    return build_server(
        config,
        resolver,
        commands,
        command_errors=errors,
        audit=AuditLog(audit_path),
        environ={"PATH": os.environ["PATH"], "OP_SESSION_x": "leak"},
        **kw,
    )


async def call(server: Any, tool: str, args: dict[str, Any]) -> Any:
    async with Client(server) as c:
        return await c.call_tool(tool, args)


async def test_tools_and_approval_metadata(config: Config, fake_resolver: FakeResolver) -> None:
    async with Client(make_server(config, fake_resolver)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert set(tools) == {"list_items", "run_with_items"}
        assert tools["run_with_items"].meta == {REQUIRES_USER_INTERACTION: True}
        assert not (tools["list_items"].meta or {}).get(REQUIRES_USER_INTERACTION)
        assert tools["list_items"].annotations.read_only_hint is True
        assert tools["run_with_items"].annotations.destructive_hint is True
        schema = tools["run_with_items"].input_schema
        assert schema["required"] == ["items", "command", "reason"]
        assert c.instructions and "never" in c.instructions.lower()


async def test_list_items_has_no_secrets(config: Config, fake_resolver: FakeResolver) -> None:
    r = await call(make_server(config, fake_resolver), "list_items", {})
    assert not r.is_error
    items = {i["alias"]: i for i in r.structured_content["items"]}
    assert set(items) == {"token", "limited", "other"}
    assert items["limited"]["uses_remaining"] == 2
    assert items["token"]["uses_remaining"] is None
    assert items["token"]["env"] == "FAKE_TOKEN"
    assert "writable by the current user" in items["token"]["warnings"][0]
    assert fake_resolver.calls == []  # listing never touches 1Password
    assert SECRET not in json.dumps(r.structured_content)


async def test_run_masks_secret_everywhere(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path, audit_path: Path
) -> None:
    server = make_server(config, fake_resolver, audit_path)
    tool = str(bin_dir / "faketool")
    for mode in ("print-env", "b64", "hex", "stderr"):
        r = await call(
            server,
            "run_with_items",
            {"items": ["token"], "command": [tool, mode], "reason": "test"},
        )
        assert not r.is_error, r.content
        data = r.structured_content
        dump = json.dumps(data)
        assert SECRET not in dump, mode
        assert data["redactions"] >= 1, mode
        assert "[REDACTED:token]" in data["stdout"] + data["stderr"]
    assert fake_resolver.calls == ["op://Dev/Fake Token/credential"] * 4
    audit_text = audit_path.read_text()
    assert SECRET not in audit_text
    records = [json.loads(line) for line in audit_text.splitlines()]
    assert [r["event"] for r in records] == ["run"] * 4
    assert records[0]["refs"] == ["op://Dev/Fake Token/credential"]
    assert records[0]["reason"] == "test"
    assert oct(audit_path.stat().st_mode & 0o777) == "0o600"


async def test_child_does_not_inherit_1password_env(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path
) -> None:
    r = await call(
        make_server(config, fake_resolver),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "op-env"], "reason": "test"},
    )
    assert r.structured_content["stdout"].strip() == "0"


async def test_exit_code_and_ok_output(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path
) -> None:
    r = await call(
        make_server(config, fake_resolver),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "ok"], "reason": "test"},
    )
    data = r.structured_content
    assert data["exit_code"] == 0
    assert data["stdout"] == "hello from faketool\n"
    assert data["redactions"] == 0
    assert data["items"] == ["token"]


async def test_refusals_never_contact_1password(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path, audit_path: Path
) -> None:
    server = make_server(config, fake_resolver, audit_path)
    cases = [
        ({"items": ["nope"], "command": ["x"]}, "unknown item"),
        ({"items": ["token"], "command": ["/bin/sh", "-c", "env"]}, "may only be used with"),
        ({"items": ["limited"], "command": [str(bin_dir / "faketool"), "b64"]}, "only allows"),
    ]
    for args, match in cases:
        r = await call(server, "run_with_items", {**args, "reason": "test"})
        assert r.is_error
        assert match in r.content[0].text
    assert fake_resolver.calls == []
    events = [json.loads(line)["event"] for line in audit_path.read_text().splitlines()]
    assert events == ["refused"] * 3


async def test_max_uses_enforced(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path
) -> None:
    server = make_server(config, fake_resolver)
    args = {"items": ["limited"], "command": [str(bin_dir / "faketool"), "ok"], "reason": "test"}
    assert not (await call(server, "run_with_items", args)).is_error
    assert not (await call(server, "run_with_items", args)).is_error
    r = await call(server, "run_with_items", args)
    assert r.is_error
    assert "max_uses" in r.content[0].text


async def test_resolver_error_is_reported(config: Config, bin_dir: Path, audit_path: Path) -> None:
    resolver = FakeResolver(error=ResolveError("1Password desktop app: denied"))
    r = await call(
        make_server(config, resolver, audit_path),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "ok"], "reason": "test"},
    )
    assert r.is_error
    assert "denied" in r.content[0].text
    assert json.loads(audit_path.read_text())["event"] == "error"


async def test_short_secret_refused(config: Config, bin_dir: Path) -> None:
    r = await call(
        make_server(config, FakeResolver(values={"op://Dev/Fake Token/credential": "abc"})),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "ok"], "reason": "test"},
    )
    assert r.is_error
    assert "cannot be masked" in r.content[0].text


async def test_output_truncated_to_limit(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path
) -> None:
    r = await call(
        make_server(config, fake_resolver),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "big"], "reason": "test"},
    )
    data = r.structured_content
    assert data["stdout_truncated"]
    assert len(data["stdout"]) == config.limits.max_output_bytes


async def test_timeout(config: Config, fake_resolver: FakeResolver, bin_dir: Path) -> None:
    r = await call(
        make_server(config, fake_resolver),
        "run_with_items",
        {
            "items": ["token"],
            "command": [str(bin_dir / "faketool"), "sleep"],
            "reason": "test",
            "timeout_seconds": 1,
        },
    )
    assert r.structured_content["timed_out"] is True
    assert r.structured_content["exit_code"] is None


async def test_replaced_binary_refused(
    config: Config, fake_resolver: FakeResolver, bin_dir: Path
) -> None:
    server = make_server(config, fake_resolver)
    (bin_dir / "faketool").write_text("#!/bin/sh\nenv\n")
    r = await call(
        server,
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "ok"], "reason": "test"},
    )
    assert r.is_error
    assert "changed since the server started" in r.content[0].text
    assert fake_resolver.calls == []


async def test_reason_required(config: Config, fake_resolver: FakeResolver, bin_dir: Path) -> None:
    r = await call(
        make_server(config, fake_resolver),
        "run_with_items",
        {"items": ["token"], "command": [str(bin_dir / "faketool"), "ok"], "reason": ""},
    )
    assert r.is_error
    assert fake_resolver.calls == []
