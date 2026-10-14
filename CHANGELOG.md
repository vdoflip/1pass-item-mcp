# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-13

### Added

- MCP server with `list_items` and `run_with_items` (marked `anthropic/requiresUserInteraction`).
- TOML allowlist: per-item secret reference, env var, allowed commands, argument prefixes,
  per-session use limits, opt-in for project-code-running tools.
- Backends: 1Password desktop app (SDK `DesktopAuth`), service account, `op` CLI.
- Command pinning by real path and SHA-256 at startup; refusal if the binary changes.
- Shell-free execution with timeouts, process-group kill and output caps.
- Masking of secrets and common encodings in output; local JSONL audit log.
- `init`, `check` (with `--resolve`) and `serve` commands.
- Claude Code plugin with a guard hook blocking direct 1Password access and config edits.

[Unreleased]: https://github.com/vdoflip/1pass-item-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vdoflip/1pass-item-mcp/releases/tag/v0.1.0
