# Contributing

Thanks for helping. This project is security-sensitive, so changes favour being
small, explicit and tested.

1. Open an issue first for anything beyond a small fix (security issues: see
   [SECURITY.md](SECURITY.md)).
2. `uv sync`, then make your change with tests. Tests must not need a real 1Password account.
3. Run `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest`.
4. Add a line under `## [Unreleased]` in `CHANGELOG.md`.

Changes that widen what an agent can reach (new tools, returning values, relaxing the
denied-executables list or config validation) need a clear rationale in the PR.
