from __future__ import annotations

import os
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from onepass_item_mcp.config import (
    ConfigError,
    default_config_path,
    executable_denied,
    load_config,
    parse_config,
    resolve_all_commands,
    resolve_command,
)

HEADER = '[onepassword]\nbackend = "desktop"\naccount = "a.1password.com"\n'


def item(**fields: object) -> str:
    base: dict[str, object] = {
        "ref": "op://V/I/f",
        "env": "TOKEN",
        "commands": ["gh"],
    }
    base.update(fields)
    lines = []
    for k, v in base.items():
        if isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        else:
            lines.append(f"{k} = {v!r}".replace("'", '"'))
    return HEADER + "[items.x]\n" + "\n".join(lines) + "\n"


def test_valid_config(config_text: str) -> None:
    cfg = parse_config(config_text)
    assert set(cfg.items) == {"token", "limited", "other"}
    assert cfg.items["limited"].max_uses == 2
    assert cfg.limits.max_output_bytes == 4096


@pytest.mark.parametrize(
    "ref",
    [
        "op://V/I/f",
        "op://My Vault/My Item/password",
        "op://V/I/section/field",
        "op://V/I/one-time password?attribute=otp",
    ],
)
def test_valid_refs(ref: str) -> None:
    parse_config(item(ref=ref))


@pytest.mark.parametrize(
    "ref",
    ["op://V/I", "op://V", "https://x/y/z", "op://V/I/f?attribute=type", "op://V/I/a/b/c", "V/I/f"],
)
def test_invalid_refs(ref: str) -> None:
    with pytest.raises(ConfigError, match="ref must look like"):
        parse_config(item(ref=ref))


@pytest.mark.parametrize(
    "env",
    ["PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "OP_SERVICE_ACCOUNT_TOKEN", "NODE_OPTIONS"],
)
def test_forbidden_env(env: str) -> None:
    with pytest.raises(ConfigError, match="not allowed"):
        parse_config(item(env=env))


def test_env_must_be_uppercase() -> None:
    with pytest.raises(ConfigError, match="UPPER_CASE"):
        parse_config(item(env="token"))


@pytest.mark.parametrize(
    "cmd",
    ["bash", "sh", "python3", "python3.12", "node", "env", "/usr/bin/env", "cat", "jq", "curl",
     "base64", "op", "sudo", "xargs", "awk", "sed", "osascript", "1pass-item-mcp"],
)  # fmt: skip
def test_denied_commands(cmd: str) -> None:
    with pytest.raises(ConfigError, match="never allowed"):
        parse_config(item(commands=[cmd]))


@pytest.mark.parametrize("cmd", ["npm", "make", "git", "docker", "terraform", "cargo"])
def test_project_code_commands_need_opt_in(cmd: str) -> None:
    with pytest.raises(ConfigError, match="allow_project_code"):
        parse_config(item(commands=[cmd]))
    parse_config(item(commands=[cmd], allow_project_code=True))


@pytest.mark.parametrize("cmd", ["gh;rm", "../gh", "g h", "", "/usr/../bin/gh"])
def test_malformed_commands(cmd: str) -> None:
    with pytest.raises(ConfigError):
        parse_config(item(commands=[cmd]))


def test_duplicate_commands() -> None:
    with pytest.raises(ConfigError, match="duplicates"):
        parse_config(item(commands=["gh", "gh"]))


def test_empty_args_prefixes_rejected() -> None:
    with pytest.raises(ConfigError, match="args_prefixes"):
        parse_config(item(args_prefixes=[[]]))


def test_bad_alias() -> None:
    text = HEADER + '[items."Bad Alias"]\nref = "op://V/I/f"\nenv = "T"\ncommands = ["gh"]\n'
    with pytest.raises(ConfigError, match="alias"):
        parse_config(text)


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ConfigError, match="Extra inputs"):
        parse_config(item(reveal=True))


def test_desktop_needs_account() -> None:
    with pytest.raises(ConfigError, match="account"):
        parse_config('[onepassword]\nbackend = "desktop"\n')


def test_other_backends() -> None:
    parse_config('[onepassword]\nbackend = "service-account"\n')
    parse_config('[onepassword]\nbackend = "cli"\nop_path = "/usr/bin/op"\n')


def test_limits_validation() -> None:
    with pytest.raises(ConfigError, match="default_timeout_seconds"):
        parse_config(HEADER + "[limits]\ndefault_timeout_seconds = 100\nmax_timeout_seconds = 10\n")


def test_invalid_toml() -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        parse_config("[onepassword\n")


def test_load_config_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_load_config_rejects_group_writable(
    write_config: Callable[[str], Path], config_text: str
) -> None:
    p = write_config(config_text)
    load_config(p)
    p.chmod(0o620)
    with pytest.raises(ConfigError, match="group- or world-writable"):
        load_config(p)
    p.chmod(0o600)
    p.parent.chmod(0o777)
    try:
        with pytest.raises(ConfigError, match="config directory"):
            load_config(p)
    finally:
        p.parent.chmod(0o700)


def test_default_config_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert default_config_path() == tmp_path / "1pass-item-mcp" / "config.toml"
    monkeypatch.setenv("ONEPASS_ITEM_MCP_CONFIG", "~/x.toml")
    assert default_config_path() == Path("~/x.toml").expanduser()


def test_resolve_command_pins_binary(bin_dir: Path) -> None:
    rc = resolve_command(str(bin_dir / "faketool"))
    assert rc.path == os.path.realpath(bin_dir / "faketool")
    assert len(rc.sha256) == 64
    assert rc.user_writable  # tmp dir belongs to us
    rc2 = resolve_command("faketool", search_path=str(bin_dir))
    assert rc2.path == rc.path


def test_resolve_command_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        resolve_command("definitely-not-a-real-tool", search_path=str(tmp_path))


def test_symlink_to_shell_is_refused(tmp_path: Path) -> None:
    link = tmp_path / "innocent"
    link.symlink_to("/bin/sh")
    with pytest.raises(ConfigError, match="never allowed"):
        resolve_command(str(link))


def test_resolve_all_commands_reports_errors(bin_dir: Path) -> None:
    text = HEADER + textwrap.dedent(
        f"""\
        [items.a]
        ref = "op://V/I/f"
        env = "A"
        commands = ["{bin_dir / "faketool"}", "missing-tool-xyz"]
        """
    )
    resolved, errors = resolve_all_commands(parse_config(text), search_path=str(bin_dir))
    assert str(bin_dir / "faketool") in resolved
    assert "missing-tool-xyz" in errors


def test_executable_denied_helper() -> None:
    assert executable_denied("/usr/local/bin/python3.13")
    assert executable_denied("PERL")
    assert not executable_denied("gh")
