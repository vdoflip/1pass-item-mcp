"""Version numbers and plugin manifests stay consistent."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from onepass_item_mcp import __version__

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

ROOT = Path(__file__).parent.parent


def test_versions_match() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    plugin = json.loads((ROOT / "claude-plugin" / ".claude-plugin" / "plugin.json").read_text())
    mcp = json.loads((ROOT / "claude-plugin" / ".mcp.json").read_text())
    assert pyproject["project"]["version"] == __version__
    assert plugin["version"] == __version__
    args = mcp["mcpServers"]["1pass-item"]["args"]
    assert f"@v{__version__}" in args[1]
    assert args[2:] == ["1pass-item-mcp", "serve"]


def test_hooks_manifest() -> None:
    hooks = json.loads((ROOT / "claude-plugin" / "hooks" / "hooks.json").read_text())
    entry = hooks["hooks"]["PreToolUse"][0]
    assert set(entry["matcher"].split("|")) >= {"Bash", "Edit", "Write"}
    assert "guard.py" in entry["hooks"][0]["command"]
    assert (ROOT / "claude-plugin" / "hooks" / "guard.py").stat().st_mode & 0o111


def test_marketplace_points_at_plugin() -> None:
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    (entry,) = market["plugins"]
    assert entry["name"] == "1pass-item-mcp"
    assert (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").is_file()
