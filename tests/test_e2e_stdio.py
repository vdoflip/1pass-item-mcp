"""End to end: the real server process over stdio, with a fake `op` CLI backend."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import make_executable
from mcp import Client, StdioServerParameters

pytestmark = pytest.mark.anyio

SECRET = "e2e-secret-value-0123456789"


async def test_stdio_round_trip(
    tmp_path: Path, bin_dir: Path, write_config: Callable[[str], Path]
) -> None:
    op = make_executable(tmp_path, "op", f"#!/bin/sh\nprintf '{SECRET}'\n")
    cfg = write_config(
        f'[onepassword]\nbackend = "cli"\nop_path = "{op}"\n'
        "[audit]\nenabled = true\n"
        f'path = "{tmp_path / "audit.jsonl"}"\n'
        f'[items.token]\nref = "op://V/I/f"\nenv = "FAKE_TOKEN"\n'
        f'commands = ["{bin_dir / "faketool"}"]\n'
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "onepass_item_mcp", "serve", "--config", str(cfg)],
    )
    async with Client(params) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert tools["run_with_items"].meta == {"anthropic/requiresUserInteraction": True}
        r = await c.call_tool(
            "run_with_items",
            {
                "items": ["token"],
                "command": [str(bin_dir / "faketool"), "print-env"],
                "reason": "e2e",
            },
        )
        assert not r.is_error, r.content
        assert r.structured_content["stdout"] == "token=[REDACTED:token]\n"
        assert SECRET not in json.dumps(r.structured_content)
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"event": "run"' in audit
    assert SECRET not in audit
