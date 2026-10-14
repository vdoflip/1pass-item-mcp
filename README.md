# 1pass-item-mcp

[![CI](https://github.com/vdoflip/1pass-item-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vdoflip/1pass-item-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/vdoflip/1pass-item-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/vdoflip/1pass-item-mcp/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small, bounded [MCP](https://modelcontextprotocol.io) server that lets an AI agent
(Claude Code, or any MCP client) **use** individual 1Password items, **one approved command
at a time, without ever seeing the secret**.

- **Explicit allowlist.** Only items listed in your config exist for the agent. Each item
  is pinned to the environment variable it goes into and the only commands that may receive it.
- **Approval on every use.** The run tool is marked
  `anthropic/requiresUserInteraction`, so Claude Code asks you **on every call, in every
  permission mode, with no "don't ask again"**. The 1Password app asks too, whenever its
  authorization has expired.
- **Never the value.** The secret goes into the child process environment only. The agent
  gets exit code and output, with the secret (and common encodings of it) masked.
- **No shell, ever.** Commands run as an argv list. Shells, interpreters, file readers,
  encoders and generic network tools can't be allowlisted.

> Not affiliated with or endorsed by 1Password / AgileBits.

```
agent ──run_with_items(items=["github"], command=["gh","api","user"], reason="…")──►
          Claude Code: approve? (every call)
                          │ yes
        policy: item allowlisted? command allowed for it? args prefix? max_uses?
                binary unchanged since startup?
                          │ ok
        1Password: resolve op://Dev/GitHub PAT/token   (1Password app prompt if needed)
                          │
        exec gh api user  with GH_TOKEN=<secret>   (no shell, own process group, timeout)
                          │
◄── exit code + stdout/stderr, secret masked, size-capped ── audit log (no secrets)
```

## Requirements

- macOS or Linux, Python 3.10+ ([`uv`](https://docs.astral.sh/uv/) recommended)
- 1Password desktop app with **Settings → Developer → Integrate with other apps** enabled
  (for the default `desktop` backend). Alternatively a service account or the `op` CLI.
- `python3` on `PATH` for the Claude Code plugin's guard hook

## Install

### Claude Code plugin (recommended)

```text
/plugin marketplace add vdoflip/1pass-item-mcp
/plugin install 1pass-item-mcp@1pass-item-mcp
```

The plugin starts the server with `uvx` (pinned to a release tag) and adds a guard hook
(see [Guard hook](#guard-hook-claude-code-plugin)).

### Any MCP client

```bash
uvx --from git+https://github.com/vdoflip/1pass-item-mcp@v0.1.0 1pass-item-mcp serve
# or, once published to PyPI:  uvx 1pass-item-mcp serve
```

```json
{
  "mcpServers": {
    "1pass-item": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/vdoflip/1pass-item-mcp@v0.1.0", "1pass-item-mcp", "serve"]
    }
  }
}
```

Clients other than Claude Code may ignore `requiresUserInteraction`. Configure them to
require approval for `run_with_items`.

## Configure

```bash
1pass-item-mcp init       # writes ~/.config/1pass-item-mcp/config.toml (mode 600)
$EDITOR ~/.config/1pass-item-mcp/config.toml
1pass-item-mcp check      # validates config, resolves and pins commands
1pass-item-mcp check --resolve github   # test-fetch one item (value is not shown)
```

```toml
[onepassword]
backend = "desktop"            # desktop | service-account | cli
account = "my.1password.com"   # as shown in the 1Password app

[limits]
default_timeout_seconds = 60
max_timeout_seconds = 300
max_output_bytes = 65536
max_items_per_call = 5

[audit]
enabled = true                 # ~/.local/state/1pass-item-mcp/audit.jsonl

[items.github]
description = "GitHub token (read-only scopes) for the gh CLI"
ref = "op://Development/GitHub PAT/token"
env = "GH_TOKEN"
commands = ["gh"]
args_prefixes = [["api", "repos/"], ["pr", "view"], ["run", "list"]]
max_uses = 20
```

| Key | Meaning |
|---|---|
| `ref` | `op://vault/item[/section]/field` (optionally `?attribute=otp`) |
| `env` | Env var the secret is injected into. Loader, shell and `OP_*` variables are rejected |
| `commands` | Executable names (resolved on `PATH` at startup) or absolute paths. Must be non-empty |
| `args_prefixes` | Optional. Arguments must start with one of these sequences. **Use it for multi-purpose CLIs** |
| `max_uses` | Optional. Uses per server session |
| `allow_project_code` | Required to allowlist tools that run agent-editable code (`npm`, `make`, `git`, `docker`, `terraform`, …) |

The config file and its directory must be owned by you and not group/world-writable.
The server reads them **once at startup**. Restart the MCP server after editing.

### Backends

| Backend | How it authenticates | Notes |
|---|---|---|
| `desktop` (default) | 1Password SDK desktop-app integration (`DesktopAuth`) | The app shows a prompt naming this process. Authorization is per process and expires after 10 min idle or when 1Password locks. Your whole account is reachable by **this process**, so the allowlist is what bounds the agent |
| `service-account` | Token in `$OP_SERVICE_ACCOUNT_TOKEN` (configurable) at startup | Token is removed from the environment after reading. Scope the service account to a dedicated vault. No interactive 1Password prompt |
| `cli` | `op read` via the 1Password CLI | Uses the CLI's own desktop integration or service account |

## Tools

| Tool | Approval | What it does |
|---|---|---|
| `list_items` | normal | Lists aliases, descriptions, refs, env var, allowed commands/args, remaining uses, warnings. Never contacts 1Password |
| `run_with_items` | **every call** | `items` (aliases), `command` (argv list), `reason` (shown to you), optional `cwd` and `timeout_seconds`. Returns `exit_code`, `stdout`, `stderr`, truncation flags, `timed_out`, `redactions` |

## Guard hook (Claude Code plugin)

The plugin adds a `PreToolUse` hook so the MCP server stays the only route to 1Password:

- Bash commands using the `op` CLI (also via full paths, `env`, `sh -c`, Python `subprocess`, …),
  `op://` references, 1Password SDKs or tokens are denied
- running `1pass-item-mcp` from the shell is denied (it can't be used to start a second
  server with a different config)
- writes to the config file/directory or to the installed plugin are denied

## Security model

**Protects against:** an agent (or a prompt injection) reading secrets into its context,
widening its own access, using items for commands you didn't intend, or running a
swapped-out binary. Each use is approved by a person, and every request is logged locally.

**Does not protect against:**

- **The allowlisted program itself.** Whatever you allowlist receives the secret. If it can
  print its environment, read arbitrary files (`/proc/self/environ`), send data to arbitrary
  hosts, or run plugins/extensions/aliases, the agent could get the secret through it. Prefer
  narrow CLIs and use `args_prefixes` (e.g. `gh` without `extension`, `alias`, or `api` to arbitrary hosts).
- **Masking is best effort.** Literal, base64 (any alignment), hex, URL, JSON-escaped and
  reversed forms are masked. Arbitrary transformations are not. The command allowlist is the
  real boundary.
- **Same-user processes.** The agent runs as you. The guard hook matches command text and can
  be evaded by obfuscation; the 1Password app prompt and per-call approval remain.
- **Output you approve.** Command output (minus the secret) goes to the model.
- **Python memory hygiene.** Secrets are dropped after use but can't be zeroed in Python.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```bash
uv sync                 # creates .venv with dev dependencies
uv run pytest           # tests use fake 1Password backends; no account needed
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Releases: bump the version in `pyproject.toml`, `src/onepass_item_mcp/__init__.py`,
`claude-plugin/.claude-plugin/plugin.json` and the tag in `claude-plugin/.mcp.json` (a test
checks they agree), update `CHANGELOG.md`, then push a `vX.Y.Z` tag. The release workflow
builds, publishes to PyPI (trusted publishing, `pypi` environment) and creates a GitHub
release.

## License

[MIT](LICENSE) © vdoflip
