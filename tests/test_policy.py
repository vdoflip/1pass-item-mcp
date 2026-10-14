from __future__ import annotations

from pathlib import Path

import pytest

from onepass_item_mcp.config import Config, resolve_all_commands
from onepass_item_mcp.policy import MAX_ARGS, Policy, PolicyError


@pytest.fixture
def policy(config: Config) -> Policy:
    commands, errors = resolve_all_commands(config)
    assert not errors
    return Policy(config, commands)


@pytest.fixture
def tool(bin_dir: Path) -> str:
    return str(bin_dir / "faketool")


def test_happy_path(policy: Policy, tool: str, tmp_path: Path) -> None:
    plan = policy.check(["token"], [tool, "ok"], cwd=str(tmp_path), timeout_seconds=3)
    assert plan.aliases == ("token",)
    assert plan.args == ("ok",)
    assert plan.timeout == 3
    assert plan.cwd == str(tmp_path.resolve())


def test_default_timeout(policy: Policy, tool: str) -> None:
    assert policy.check(["token"], [tool]).timeout == 5


@pytest.mark.parametrize(
    ("items", "match"),
    [
        ([], "at least one"),
        (["nope"], "unknown item"),
        (["token", "token"], "duplicate"),
        (["a", "b", "c", "d", "e", "f"], "at most 5"),
    ],
)
def test_bad_items(policy: Policy, tool: str, items: list[str], match: str) -> None:
    with pytest.raises(PolicyError, match=match):
        policy.check(items, [tool])


def test_command_not_allowed_for_item(policy: Policy, bin_dir: Path) -> None:
    with pytest.raises(PolicyError, match="may only be used with"):
        policy.check(["token"], [str(bin_dir / "othertool")])


def test_command_must_be_allowed_for_every_item(policy: Policy, tool: str) -> None:
    with pytest.raises(PolicyError, match="'other' may only be used with"):
        policy.check(["token", "other"], [tool, "ok"])


def test_shell_is_never_reachable(policy: Policy) -> None:
    with pytest.raises(PolicyError, match="may only be used with"):
        policy.check(["token"], ["/bin/sh", "-c", "echo $FAKE_TOKEN"])


def test_args_prefixes(policy: Policy, tool: str) -> None:
    policy.check(["limited"], [tool, "ok"])
    policy.check(["limited"], [tool, "print-env", "extra"])
    with pytest.raises(PolicyError, match="only allows arguments"):
        policy.check(["limited"], [tool, "b64"])
    with pytest.raises(PolicyError, match="only allows arguments"):
        policy.check(["limited"], [tool])


def test_max_uses(policy: Policy, tool: str) -> None:
    assert policy.remaining_uses("limited") == 2
    assert policy.remaining_uses("token") is None
    policy.record_use(("limited",))
    policy.record_use(("limited",))
    assert policy.remaining_uses("limited") == 0
    with pytest.raises(PolicyError, match="max_uses"):
        policy.check(["limited"], [tool, "ok"])


def test_empty_and_huge_commands(policy: Policy, tool: str) -> None:
    with pytest.raises(PolicyError, match="must not be empty"):
        policy.check(["token"], [])
    with pytest.raises(PolicyError, match="more than"):
        policy.check(["token"], [tool] + ["x"] * MAX_ARGS)
    with pytest.raises(PolicyError, match="NUL"):
        policy.check(["token"], [tool, "a\0b"])


@pytest.mark.parametrize("cwd", ["relative/dir", "/definitely/not/here"])
def test_bad_cwd(policy: Policy, tool: str, cwd: str) -> None:
    with pytest.raises(PolicyError, match="cwd"):
        policy.check(["token"], [tool], cwd=cwd)


@pytest.mark.parametrize("timeout", [0, 11, -5])
def test_bad_timeout(policy: Policy, tool: str, timeout: int) -> None:
    with pytest.raises(PolicyError, match="timeout_seconds"):
        policy.check(["token"], [tool], timeout_seconds=timeout)


def test_uninstalled_command(config: Config, tool: str) -> None:
    with pytest.raises(PolicyError, match="not installed"):
        Policy(config, {}).check(["token"], [tool])


def test_env_collision(tmp_path: Path, tool: str) -> None:
    from onepass_item_mcp.config import parse_config

    cfg = parse_config(
        '[onepassword]\nbackend = "cli"\n'
        f'[items.a]\nref = "op://V/A/f"\nenv = "SAME"\ncommands = ["{tool}"]\n'
        f'[items.b]\nref = "op://V/B/f"\nenv = "SAME"\ncommands = ["{tool}"]\n'
    )
    commands, _ = resolve_all_commands(cfg)
    with pytest.raises(PolicyError, match="same environment variable"):
        Policy(cfg, commands).check(["a", "b"], [tool])


def test_binary_changed_after_startup(policy: Policy, tool: str) -> None:
    plan = policy.check(["token"], [tool, "ok"])
    Policy.verify_binary(plan.command)
    Path(tool).write_text("#!/bin/sh\nprintenv\n")
    with pytest.raises(PolicyError, match="changed since the server started"):
        Policy.verify_binary(plan.command)
