from __future__ import annotations

import os
from pathlib import Path

import pytest

from onepass_item_mcp.runner import child_environment, run_command

pytestmark = pytest.mark.anyio


def test_child_environment_strips_1password_and_loader_vars() -> None:
    env = child_environment(
        {
            "PATH": "/bin",
            "OP_SERVICE_ACCOUNT_TOKEN": "x",
            "OP_SESSION_abc": "y",
            "LD_PRELOAD": "evil.so",
            "DYLD_INSERT_LIBRARIES": "evil.dylib",
            "ONEPASS_ITEM_MCP_CONFIG": "/x",
            "KEEP": "1",
        },
        {"FAKE_TOKEN": "secret"},
    )
    assert env == {"PATH": "/bin", "KEEP": "1", "FAKE_TOKEN": "secret"}


async def test_runs_without_shell(bin_dir: Path) -> None:
    out = await run_command(
        str(bin_dir / "faketool"),
        ["$FAKE_TOKEN", "*", "&&", "reboot"],
        env={"PATH": os.environ["PATH"], "FAKE_TOKEN": "x"},
        cwd=None,
        timeout=5,
        capture_limit=4096,
    )
    assert out.exit_code == 0
    assert out.stdout.decode().strip() == "args: $FAKE_TOKEN * && reboot"


async def test_exit_code_and_stderr(bin_dir: Path) -> None:
    out = await run_command(
        str(bin_dir / "faketool"),
        ["stderr"],
        env={"PATH": os.environ["PATH"], "FAKE_TOKEN": "tok"},
        cwd=None,
        timeout=5,
        capture_limit=4096,
    )
    assert out.exit_code == 3
    assert out.stderr == b"oops tok\n"
    assert not out.timed_out


async def test_timeout_kills_process_group(bin_dir: Path) -> None:
    out = await run_command(
        str(bin_dir / "faketool"),
        ["sleep"],
        env={"PATH": os.environ["PATH"]},
        cwd=None,
        timeout=0.5,
        capture_limit=4096,
    )
    assert out.timed_out
    assert out.exit_code is None
    assert out.duration_seconds < 10


async def test_output_is_capped_without_blocking(bin_dir: Path) -> None:
    out = await run_command(
        str(bin_dir / "faketool"),
        ["big"],
        env={"PATH": os.environ["PATH"]},
        cwd=None,
        timeout=20,
        capture_limit=1000,
    )
    assert out.exit_code == 0
    assert len(out.stdout) == 1000
    assert out.stdout_truncated


async def test_cwd(bin_dir: Path, tmp_path: Path) -> None:
    out = await run_command(
        str(bin_dir / "faketool"),
        ["pwd"],
        env={"PATH": os.environ["PATH"]},
        cwd=str(tmp_path),
        timeout=5,
        capture_limit=4096,
    )
    assert Path(out.stdout.decode().strip()).resolve() == tmp_path.resolve()
