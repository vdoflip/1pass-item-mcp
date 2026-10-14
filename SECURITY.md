# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately via
[GitHub security advisories](https://github.com/vdoflip/1pass-item-mcp/security/advisories/new).
Include steps to reproduce, the affected version, and the impact you expect.

You should get an acknowledgement within a few days. Fixes are released as patch versions
and credited in the changelog unless you prefer otherwise.

## Scope

In scope: any way for an MCP client/agent to

- obtain a secret value (or a usable encoding of it) through this server's tools,
- use an item that isn't allowlisted, with a command or arguments that aren't allowed, or more
  often than `max_uses`,
- run a tool call without the approval metadata, or get around policy checks,
- make the server read a config it shouldn't trust,
- bypass the plugin's guard hook in ways that aren't simple text obfuscation.

Out of scope (documented limitations, see README "Security model"): secrets leaked by an
allowlisted program's own features, arbitrary transformations of output that defeat
best-effort masking, and attacks that already require code execution as the user outside
the agent.

## Supported versions

Only the latest release receives fixes.
