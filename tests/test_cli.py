from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import make_executable

from onepass_item_mcp import __version__, cli
from onepass_item_mcp.config import EXAMPLE_CONFIG, parse_config


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_init_writes_private_example(tmp_path: Path) -> None:
    p = tmp_path / "new" / "config.toml"
    assert cli.main(["init", "--config", str(p)]) == 0
    assert p.read_text() == EXAMPLE_CONFIG
    assert p.stat().st_mode & 0o777 == 0o600
    assert cli.main(["--config", str(p), "init"]) == 1  # refuses to overwrite
    assert cli.main(["init", "--config", str(p), "--force"]) == 0


def test_example_config_is_valid() -> None:
    cfg = parse_config(EXAMPLE_CONFIG)
    assert cfg.items == {}


def test_init_uses_default_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cli.main(["init"]) == 0
    assert (tmp_path / "1pass-item-mcp" / "config.toml").is_file()


def test_check_ok(
    write_config: Callable[[str], Path], config_text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    p = write_config(config_text)
    assert cli.main(["check", "--config", str(p)]) == 0
    out = capsys.readouterr().out
    assert "[token]" in out
    assert "sha256:" in out
    assert "FAKE_TOKEN" in out


def test_check_reports_missing_command(
    write_config: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    p = write_config(
        '[onepassword]\nbackend = "cli"\n'
        '[items.a]\nref = "op://V/I/f"\nenv = "A"\ncommands = ["no-such-tool-xyz"]\n'
    )
    assert cli.main(["check", "--config", str(p)]) == 1
    assert "ERROR" in capsys.readouterr().out


def test_check_resolve_does_not_print_value(
    write_config: Callable[[str], Path],
    tmp_path: Path,
    bin_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    op = make_executable(tmp_path, "op", "#!/bin/sh\nprintf 'top-secret-value'\n")
    p = write_config(
        f'[onepassword]\nbackend = "cli"\nop_path = "{op}"\n'
        f'[items.a]\nref = "op://V/I/f"\nenv = "A"\ncommands = ["{bin_dir / "faketool"}"]\n'
    )
    assert cli.main(["check", "--config", str(p), "--resolve", "a"]) == 0
    out = capsys.readouterr()
    assert "16-character value (not shown)" in out.out
    assert "top-secret-value" not in out.out + out.err
    assert cli.main(["check", "--config", str(p), "--resolve", "missing"]) == 1


def test_bad_config_exit_code(
    write_config: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    p = write_config("[onepassword]\nbackend = 'nope'\n")
    assert cli.main(["check", "--config", str(p)]) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_serve_wires_everything(
    write_config: Callable[[str], Path],
    config_text: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.server.mcpserver import MCPServer

    ran: dict[str, Any] = {}

    def fake_run(self: MCPServer, transport: str = "stdio", **kw: Any) -> None:
        ran["transport"] = transport
        ran["name"] = self.name

    monkeypatch.setattr(MCPServer, "run", fake_run)
    p = write_config(config_text)
    assert cli.main(["--config", str(p)]) == 0
    assert ran == {"transport": "stdio", "name": "1pass-item-mcp"}


def test_serve_service_account_without_token(
    write_config: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    p = write_config('[onepassword]\nbackend = "service-account"\n')
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ
    assert cli.main(["serve", "--config", str(p)]) == 2
    assert "OP_SERVICE_ACCOUNT_TOKEN" in capsys.readouterr().err
