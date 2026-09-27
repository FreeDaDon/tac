# Add /api/version endpoint returning the toolkit version

The dashboard has no way to tell which version of the toolkit is running. When I run several
checkouts (main plus worktrees) I can't tell from the UI which build I'm looking at.

## Request

Add a read-only endpoint `GET /api/version` to the dashboard server that returns:

```json
{"name": "tac", "version": "<version from pyproject.toml>"}
```

- Read `project.name` and `project.version` from the repository's `pyproject.toml` (use `tomllib`, no new dependency).
- Read the file once at startup and cache it; do not read it on every request.
- If the file or the version key is missing, return `"version": "unknown"` with HTTP 200 instead of failing.
- Show the version in the dashboard footer as `tac v<version>`.

## Acceptance criteria

- `GET /api/version` returns 200 and the JSON above with the version from `pyproject.toml`.
- Unit tests cover the normal case and the missing-version case.
- The footer shows the version.
- `uv run ruff check .`, `uv run mypy adws core`, `uv run pytest -q` and the client build pass.
