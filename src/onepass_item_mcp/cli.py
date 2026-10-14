"""Command line: `serve` (stdio MCP server), `check` (validate config), `init` (write example)."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import anyio

from onepass_item_mcp import NAME, __version__
from onepass_item_mcp.audit import AuditLog
from onepass_item_mcp.config import (
    EXAMPLE_CONFIG,
    Config,
    ConfigError,
    default_config_path,
    default_state_dir,
    load_config,
    resolve_all_commands,
)
from onepass_item_mcp.redact import SecretTooShortError, secret_variants
from onepass_item_mcp.resolver import ResolveError, build_resolver

log = logging.getLogger(NAME)


def _audit_for(cfg: Config) -> AuditLog:
    if not cfg.audit.enabled:
        return AuditLog(None)
    path = (
        Path(cfg.audit.path).expanduser() if cfg.audit.path else default_state_dir() / "audit.jsonl"
    )
    return AuditLog(path)


def cmd_serve(args: argparse.Namespace) -> int:
    from onepass_item_mcp.server import build_server  # noqa: PLC0415 (keeps check/init fast)

    cfg = load_config(args.config)
    commands, errors = resolve_all_commands(cfg)
    for entry, err in errors.items():
        log.warning("command %r unavailable: %s", entry, err)
    for rc in commands.values():
        if rc.user_writable:
            log.warning("%s is writable by the current user; it is pinned by hash", rc.path)
    resolver = build_resolver(cfg.onepassword)
    server = build_server(cfg, resolver, commands, command_errors=errors, audit=_audit_for(cfg))
    log.info("%s %s serving %d item(s) over stdio", NAME, __version__, len(cfg.items))
    server.run("stdio")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    commands, errors = resolve_all_commands(cfg)
    print(f"config:  {args.config}  (ok)")
    print(f"backend: {cfg.onepassword.backend}")
    print(f"items:   {len(cfg.items)}")
    for alias, item in sorted(cfg.items.items()):
        print(f"\n[{alias}] {item.description}")
        print(f"  ref: {item.ref}\n  env: {item.env}")
        if item.args_prefixes:
            print(f"  args_prefixes: {item.args_prefixes}")
        if item.max_uses:
            print(f"  max_uses: {item.max_uses}")
        for c in item.commands:
            if c in errors:
                print(f"  command {c}: ERROR {errors[c]}")
            else:
                rc = commands[c]
                note = "  (writable by you: pinned by hash)" if rc.user_writable else ""
                print(f"  command {c}: {rc.path} sha256:{rc.sha256[:12]}{note}")
    if args.resolve:
        if args.resolve not in cfg.items:
            print(f"\nunknown item {args.resolve!r}", file=sys.stderr)
            return 1
        item = cfg.items[args.resolve]
        print(f"\nresolving {args.resolve} via 1Password (approve the prompt if one appears)...")
        try:
            value = anyio.run(build_resolver(cfg.onepassword).resolve, item.ref)
            secret_variants(value)
        except (ResolveError, SecretTooShortError) as e:
            print(f"FAILED: {e}", file=sys.stderr)
            return 1
        print(f"ok: resolved a {len(value)}-character value (not shown)")
    return 1 if errors else 0


def cmd_init(args: argparse.Namespace) -> int:
    path: Path = args.config
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(EXAMPLE_CONFIG)
    os.chmod(path, 0o600)
    print(f"wrote {path}; edit it, then run: {NAME} check")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Global options are accepted before or after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config",
        type=Path,
        default=argparse.SUPPRESS,
        help="config file (default: $ONEPASS_ITEM_MCP_CONFIG or "
        "~/.config/1pass-item-mcp/config.toml)",
    )
    common.add_argument(
        "--log-level", default=argparse.SUPPRESS, choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    p = argparse.ArgumentParser(
        prog=NAME,
        description="Bounded MCP server for individual, allowlisted 1Password items.",
        parents=[common],
    )
    # No set_defaults for --config/--log-level: the actions are shared with the subparsers.
    p.set_defaults(resolve=None, force=False)
    p.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", parents=[common], help="run the MCP server over stdio (default)")
    c = sub.add_parser("check", parents=[common], help="validate the config and commands")
    c.add_argument("--resolve", metavar="ALIAS", help="also test fetching ALIAS (value not shown)")
    i = sub.add_parser("init", parents=[common], help="write an example config (mode 600)")
    i.add_argument("--force", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.config = (getattr(args, "config", None) or default_config_path()).expanduser()
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(args, "log_level", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
    )
    cmd = args.cmd or "serve"
    try:
        if cmd == "init":
            return cmd_init(args)
        if cmd == "check":
            return cmd_check(args)
        return cmd_serve(args)
    except (ConfigError, ResolveError) as e:
        print(f"{NAME}: {e}", file=sys.stderr)
        return 2
