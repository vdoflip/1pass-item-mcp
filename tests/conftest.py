from __future__ import annotations

import os
import stat
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from onepass_item_mcp.config import Config, parse_config

SECRET = "s3cr3t-T0ken_value-1234567890"

FAKE_TOOL = textwrap.dedent(
    """\
    #!/bin/sh
    case "$1" in
      ok) echo "hello from faketool" ;;
      print-env) printf 'token=%s\\n' "$FAKE_TOKEN" ;;
      b64) printf '%s' "$FAKE_TOKEN" | base64 ;;
      hex) printf '%s' "$FAKE_TOKEN" | od -An -tx1 | tr -d ' \\n' ;;
      stderr) printf 'oops %s\\n' "$FAKE_TOKEN" >&2; exit 3 ;;
      sleep) sleep 30 ;;
      big) i=0; while [ $i -lt 20000 ]; do echo "line $i padding padding padding"; i=$((i+1)); done ;;
      op-env) env | grep -c '^OP_' ;;
      pwd) pwd ;;
      *) echo "args: $*" ;;
    esac
    """
)


def make_executable(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def bin_dir(tmp_path: Path) -> Path:
    d = tmp_path / "bin"
    d.mkdir()
    make_executable(d, "faketool", FAKE_TOOL)
    make_executable(d, "othertool", "#!/bin/sh\necho other\n")
    return d


@pytest.fixture
def config_text(bin_dir: Path) -> str:
    tool = bin_dir / "faketool"
    other = bin_dir / "othertool"
    return textwrap.dedent(
        f"""\
        [onepassword]
        backend = "desktop"
        account = "example.1password.com"

        [limits]
        default_timeout_seconds = 5
        max_timeout_seconds = 10
        max_output_bytes = 4096

        [items.token]
        description = "fake token"
        ref = "op://Dev/Fake Token/credential"
        env = "FAKE_TOKEN"
        commands = ["{tool}"]

        [items.limited]
        ref = "op://Dev/Limited/password"
        env = "LIMITED"
        commands = ["{tool}"]
        args_prefixes = [["ok"], ["print-env"]]
        max_uses = 2

        [items.other]
        ref = "op://Dev/Other/password"
        env = "OTHER"
        commands = ["{other}"]
        """
    )


@pytest.fixture
def config(config_text: str) -> Config:
    return parse_config(config_text)


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[[str], Path]:
    def _write(text: str) -> Path:
        d = tmp_path / "cfg"
        d.mkdir(mode=0o700, exist_ok=True)
        p = d / "config.toml"
        p.write_text(text)
        p.chmod(0o600)
        return p

    return _write


class FakeResolver:
    def __init__(self, values: dict[str, str] | None = None, error: Exception | None = None):
        self.values = values or {}
        self.error = error
        self.calls: list[str] = []

    async def resolve(self, ref: str) -> str:
        self.calls.append(ref)
        if self.error:
            raise self.error
        return self.values.get(ref, SECRET)


@pytest.fixture
def fake_resolver() -> FakeResolver:
    return FakeResolver()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.delenv("ONEPASS_ITEM_MCP_CONFIG", raising=False)
    for k in list(os.environ):
        if k.startswith("OP_"):
            monkeypatch.delenv(k)
