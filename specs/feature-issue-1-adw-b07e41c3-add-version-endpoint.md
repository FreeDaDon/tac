# Feature: Add `/api/version` endpoint and dashboard footer

## Metadata
issue_number: `1`
adw_id: `b07e41c3`
issue_file: `/root/projects/tac/agent/runs/b07e41c3/inputs/issue.md`

## Feature Description
Add a read-only `GET /api/version` endpoint to the dashboard API that reports the toolkit's
`name` and `version` (sourced from `pyproject.toml`), and show that version in the dashboard's
footer as `tac v<version>`.

## User Story
As a solo operator running several checkouts (main plus worktrees)
I want to see which toolkit version the running dashboard is built from
So that I can tell at a glance which build I'm looking at without cross-checking git manually

## Problem Statement
The dashboard has no way to tell which version of the toolkit is running. With multiple worktrees
each running their own dashboard instance, there is no visual signal distinguishing one build from
another.

## Solution Statement
Add a small deterministic module that reads `project.name` / `project.version` from the
repository's `pyproject.toml` using `tomllib` (stdlib, no new dependency), following the existing
`app/server/dashboard/{kpis,worktrees}.py` pattern of a pure function taking `root: Path`. Read it
once in `create_app()` and cache the result on `app.state`, so the `/api/version` endpoint serves
the cached value instead of re-reading the file per request. Missing file or missing version key
degrades to `"version": "unknown"` with HTTP 200, matching the toolkit's rule that corrupt/partial
files never break an endpoint (see `app/README.md`). On the client, add a `version()` API call and
a small footer view, following the existing `views/header.ts` pattern, rendered once at startup
(the version cannot change without a server restart, so no polling is needed).

## Relevant Files
Use these files to implement the feature:

- `app/server/dashboard/main.py` - FastAPI app factory; register the new endpoint here, following
  the existing `@app.get("/api/...")` handlers (e.g. `get_kpis`, `get_worktrees`); compute and cache
  the version once during `create_app()`.
- `app/server/dashboard/kpis.py` - example of the module pattern to follow: a pure `load_*(root: Path)`
  function with no FastAPI/HTTP concerns, degrading gracefully when the source file is missing.
- `app/server/dashboard/worktrees.py` - another example of the same pattern (`list_worktrees(root)`),
  reused for reading env files under `root`.
- `app/server/tests/conftest.py` - the `root` fixture (`tmp_path`-based project root) and `client` /
  `auth_client` fixtures used by `test_api.py`; the version tests extend this fixture with a
  `pyproject.toml`.
- `app/server/tests/test_api.py` - existing endpoint tests; add `/api/version` tests alongside the
  other `GET /api/...` tests, following the same `client.get(...)` + assertion style.
- `pyproject.toml` - the source of truth for `project.name` / `project.version`; the shape to parse
  (`[project] name = "tac-toolkit"`, `version = "0.1.0"`).
- `app/README.md` - endpoints table to update with the new route (also a conditional doc to read
  when touching `app/`).
- `app/client/src/api.ts` - typed `fetch` wrappers; add `version()` here following the existing
  `health()` / `kpis()` entries.
- `app/client/src/types.ts` - response types; add a `Version` interface next to `Health`.
- `app/client/src/main.ts` - app bootstrap and `AppState`; add `version` to state, fetch it once at
  startup (not on the `POLL_MS` interval, since it cannot change without a restart), and mount the
  new footer slot.
- `app/client/src/views/header.ts` - closest existing example of a small view module (`renderHeader`)
  to model `renderFooter` on: same `h(...)` composition style, same file layout.
- `app/client/src/dom.ts` - the `h()` hyperscript helper used by every view.
- `app/client/src/style.css` - add minimal footer styling consistent with existing `.topbar` /
  `.badge` rules.
- `.claude/commands/test_e2e.md` - E2E runner contract/format the new spec must satisfy.
- `.claude/commands/e2e/test_dashboard_loads.md` - format reference (User Story, numbered Test Steps
  with **Verify** lines, Success Criteria) for the new E2E spec.

### New Files
- `app/server/dashboard/version.py` - `load_version(root: Path) -> dict[str, str]`: reads
  `root / "pyproject.toml"` with `tomllib`, returns `{"name": ..., "version": ...}`, falling back to
  `"unknown"` for a missing file, unparseable TOML, or a missing `project.name` / `project.version`
  key.
- `app/server/tests/test_version.py` - unit tests for `load_version` covering the normal case, missing
  file, missing version key, and malformed TOML.
- `app/client/src/views/footer.ts` - `renderFooter(version: Version | null): HTMLElement`, showing
  `tac v<version>` (or a muted placeholder before the first successful fetch).
- `.claude/commands/e2e/test_version_footer.md` - new E2E spec verifying the footer shows the version
  string, modeled on `test_dashboard_loads.md`.

## Implementation Plan
### Phase 1: Foundation
Add the deterministic `load_version` helper and its unit tests. No FastAPI or client code depends on
this yet, so it can be verified in isolation first.

### Phase 2: Core Implementation
Wire `load_version` into `create_app()` (call once, cache on `app.state.version`), add the
`GET /api/version` endpoint that returns the cached dict, and add server-side endpoint tests via the
existing `client` / `auth_client` fixtures.

### Phase 3: Integration
Add the client type, API call, and footer view; mount the footer in `main.ts`; update
`app/README.md`'s endpoint table; add and run the new E2E spec.

## Step by Step Tasks
IMPORTANT: Execute every step in order, top to bottom.

### 1. Add `load_version` and its unit tests
- Create `app/server/dashboard/version.py`:
  ```python
  """Read project.name / project.version from pyproject.toml (read once, cached by the caller)."""

  from __future__ import annotations

  import tomllib
  from pathlib import Path
  from typing import Any


  def load_version(root: Path) -> dict[str, str]:
      path = root / "pyproject.toml"
      try:
          with path.open("rb") as f:
              data: dict[str, Any] = tomllib.load(f)
      except (OSError, tomllib.TOMLDecodeError):
          return {"name": "tac", "version": "unknown"}
      project = data.get("project", {})
      name = project.get("name") if isinstance(project, dict) else None
      version = project.get("version") if isinstance(project, dict) else None
      return {
          "name": name if isinstance(name, str) and name else "tac",
          "version": version if isinstance(version, str) and version else "unknown",
      }
  ```
  Note the issue's example response uses `"name": "tac"` even though `pyproject.toml`'s
  `project.name` is `"tac-toolkit"` — treat `"name"` as a fixed literal `"tac"` in the response, not
  the parsed project name, so the acceptance JSON shape matches exactly. Only `version` comes from
  the parsed file. Simplify `load_version` to return `{"version": <parsed or "unknown">}` and let the
  caller add the fixed `"name": "tac"`, avoiding an unused parsed name entirely.
- Create `app/server/tests/test_version.py`:
  - `test_load_version_normal(tmp_path)`: write a `pyproject.toml` with `[project]\nname = "x"\nversion = "9.9.9"`, assert `load_version(tmp_path) == {"version": "9.9.9"}`.
  - `test_load_version_missing_file(tmp_path)`: no `pyproject.toml` written, assert `version == "unknown"`.
  - `test_load_version_missing_key(tmp_path)`: `[project]\nname = "x"` with no `version` key, assert `version == "unknown"`.
  - `test_load_version_malformed_toml(tmp_path)`: write `not = [valid toml`, assert `version == "unknown"` (no exception raised).

### 2. Wire the endpoint into the FastAPI app
- In `app/server/dashboard/main.py`:
  - Add `from . import version as version_mod  # noqa: E402` alongside the other `from . import ...` lines.
  - Inside `create_app()`, right after `store = EventStore(settings.db_path)`, add:
    ```python
    version_info = {"name": "tac", **version_mod.load_version(settings.root)}
    app.state.version = version_info
    ```
    This reads the file exactly once per app instance (i.e. once at server startup), matching the
    issue's "read once at startup and cache it" requirement.
  - Add the endpoint next to the other simple `GET` routes (e.g. after `get_worktrees`):
    ```python
    @app.get("/api/version")
    def get_version() -> dict[str, str]:
        return version_info
    ```
    (closes over the cached `version_info`; no per-request file I/O.)

### 3. Add server-side endpoint tests
- In `app/server/tests/test_api.py`, add tests using the existing `client` fixture:
  - `test_version_normal`: the `root` fixture's `tmp_path` needs a `pyproject.toml`; either extend the
    shared `root` fixture in `conftest.py` to write one (`[project]\nname = "tac-toolkit"\nversion = "9.9.9-test"`)
    or add a small local fixture that builds its own `create_app(root=...)` with a fresh `tmp_path`
    containing a `pyproject.toml`. Prefer extending the shared `root` fixture (simplest, and every
    other test in the file already depends on it) — add the file write next to the other `tmp_path`
    writes in `conftest.py`'s `root` fixture. Assert `GET /api/version` returns `200` and
    `{"name": "tac", "version": "9.9.9-test"}`.
  - `test_version_missing_pyproject`: build a separate `TestClient` with `create_app(root=<a fresh
    tmp_path with no pyproject.toml>, db_path=...)`, assert `200` and `{"name": "tac", "version": "unknown"}`.

### 4. Update `app/README.md`
- Add a row to the Endpoints table: `| GET | /api/version | \`{name, version}\` from pyproject.toml, read once at startup and cached |`.

### 5. Add the client type and API call
- In `app/client/src/types.ts`, add:
  ```ts
  export interface Version {
    name: string;
    version: string;
  }
  ```
- In `app/client/src/api.ts`, add to the `api` object: `version: () => get<Version>("/api/version"),` and add `Version` to the `import type { ... } from "./types"` list.

### 6. Add the footer view
- Create `app/client/src/views/footer.ts`:
  ```ts
  import { h } from "../dom";
  import type { Version } from "../types";

  export function renderFooter(version: Version | null): HTMLElement {
    return h(
      "footer",
      { class: "footer" },
      h("span", { class: "muted" }, version ? `${version.name} v${version.version}` : "…"),
    );
  }
  ```
- In `app/client/src/style.css`, add a minimal `.footer` rule consistent with the existing muted/badge
  styling (small text, top border, subdued color — match whatever variables `.topbar` already uses).

### 7. Wire the footer into `main.ts`
- Add `version: Version | null` to `AppState` and to the initial `state` object (`version: null`).
- Import `Version` in the `import type { ... } from "./types"` list and `renderFooter` from `./views/footer`.
- Add `slots.footer = h("div")` to the `slots` object and append it after `slots.drawer` in the initial `root.append(...)` call.
- In `renderAll()`, add `slots.footer.replaceChildren(renderFooter(state.version));`.
- Fetch the version once, not on the `POLL_MS` timer: after the existing `renderAll(); void refresh(); socket.start();` calls at the bottom of the file, add:
  ```ts
  void settle(api.version()).then((v) => {
    state.version = v;
    slots.footer.replaceChildren(renderFooter(state.version));
  });
  ```

### 8. Add the E2E spec
- Create `.claude/commands/e2e/test_version_footer.md`, modeled on `.claude/commands/e2e/test_dashboard_loads.md`:
  ```md
  # E2E Test: Version Footer

  Verify the dashboard footer shows the running toolkit version.

  ## User Story

  As a solo operator running several checkouts (main plus worktrees)
  I want to see the toolkit version in the dashboard footer
  So that I know which build I'm looking at without checking git manually

  ## Test Steps

  1. Navigate to the `Application URL`
  2. Take a screenshot of the initial state
  3. **Verify** a footer element is visible at the bottom of the page
  4. **Verify** the footer text matches the pattern `tac v<something>` (e.g. `tac v0.1.0`)
  5. **Verify** the footer text is not empty, "undefined", or "null"
  6. Take a screenshot of the footer
  7. **Verify** there are no uncaught JavaScript errors in the browser console

  ## Success Criteria
  - The footer is visible and shows `tac v<version>` with a non-empty version
  - No uncaught console errors
  - 2 screenshots are taken
  ```

### 9. Run validation
- Run every command in `Validation Commands` and fix any failure before finishing.

## Testing Strategy
### Unit Tests
- `app/server/tests/test_version.py`: `load_version` normal case, missing file, missing key,
  malformed TOML — asserts the exact returned dict shape (`{"version": ...}`) in every case, never
  raising.
- `app/server/tests/test_api.py`: `GET /api/version` returns `200` with `{"name": "tac", "version":
  ...}` for both a populated `pyproject.toml` and a missing one; confirms the endpoint is not
  token-protected (matches the other read-only `GET` endpoints).

### Edge Cases
- `pyproject.toml` absent entirely -> `"version": "unknown"`, HTTP 200 (not 404/500).
- `pyproject.toml` present but missing `[project]` table or `version` key -> `"unknown"`.
- `pyproject.toml` present but not valid TOML -> caught, `"unknown"`, no exception surfaces to the
  client.
- `version` value is present but not a string (e.g. a TOML integer/table) -> treated as missing,
  `"unknown"`.
- Client: `api.version()` fails (network error before first paint) -> footer shows a muted placeholder
  (`"…"`) rather than throwing, via the existing `settle()` helper used elsewhere in `main.ts`.

## Security Considerations
- Read-only, no request body, no path or query parameters — no injection surface.
- The endpoint reads a single fixed, repo-relative path (`settings.root / "pyproject.toml"`); no
  user- or model-supplied path ever reaches `load_version`, so no path traversal risk.
- Matches the existing convention that GET endpoints are not token-protected (loopback bind + host
  allow-list + CORS, per `app/README.md`'s Security notes); the version string is not sensitive.
- No new dependency: `tomllib` is stdlib in Python 3.12+ (this project requires `>=3.12`).
- Cached at startup, so a hostile or corrupted `pyproject.toml` cannot cause repeated file I/O or a
  per-request crash; a parse failure is caught and degrades to `"unknown"`, never a 500.

## Rollback
- Revert the commit(s) adding `app/server/dashboard/version.py`, the `/api/version` route in
  `main.py`, and the client footer changes. Fully additive change: no migrations, no config flags, no
  data written anywhere. Removing the route and footer fully reverts behavior with no residual state.

## Acceptance Criteria
- `GET /api/version` returns HTTP 200 and `{"name": "tac", "version": "<value from pyproject.toml>"}`
  when `pyproject.toml` has a `project.version`.
- `GET /api/version` returns HTTP 200 and `{"name": "tac", "version": "unknown"}` when
  `pyproject.toml` is missing or has no `project.version`.
- The file is read once at startup (inside `create_app()`), not on every request to `/api/version`.
- The dashboard footer shows `tac v<version>` once the client fetches `/api/version`.
- `uv run ruff check .`, `uv run mypy adws core`, `uv run pytest -q`, and
  `cd app/client && npx tsc --noEmit && npm run build` all pass.
- The new E2E spec `.claude/commands/e2e/test_version_footer.md` passes.

## Validation Commands
Execute every command to validate the feature works correctly with zero regressions.

- `uv run ruff check .` - lint
- `uv run mypy adws core` - type check
- `uv run pytest -q` - unit and integration tests
- `cd app/client && npx tsc --noEmit && npm run build` - client type check and build
- Read `.claude/commands/test_e2e.md`, then execute `.claude/commands/e2e/test_version_footer.md` - E2E validation

## Notes
- No new dependency: `tomllib` is Python 3.12 stdlib, matching `requires-python = ">=3.12"` in
  `pyproject.toml`. `uv add` is not needed.
- The issue's example JSON uses `"name": "tac"` while the actual `pyproject.toml` has
  `project.name = "tac-toolkit"`; the plan treats `"tac"` as the fixed literal for the response name
  (matching the issue's acceptance JSON exactly) rather than echoing the parsed project name. If a
  future maintainer wants the real project name reflected instead, that is a follow-up, not part of
  this issue's acceptance criteria.
- No embedded instructions beyond the feature description were found in the issue body; nothing was
  ignored.
