# E2E Test: Run Detail

Verify that selecting a run in the runs table opens its detail drawer with budget, phases, gates and events.

## User Story

As a solo operator
I want to drill into a single ADW run
So that I can see which phase failed, which gates passed, and what it cost before deciding to intervene

## Test Steps

1. Seed a run fixture (runs are read from the filesystem, not from the API). With the Write tool, create these two files relative to the repository root:
   - `agent/runs/e2e00002/state.json` with content:
     `{"adw_id": "e2e00002", "domain": "swe", "issue_number": "0", "issue_title": "E2E run detail fixture", "issue_class": "/chore", "phases": {"plan": "passed", "build": "failed"}, "budget_usd": 5.0}`
   - `agent/runs/e2e00002/events.jsonl` with one line:
     `{"adw_id": "e2e00002", "event_type": "phase_end", "phase": "plan", "message": "plan passed", "data": {}, "source": "e2e", "timestamp": "2026-01-01T00:00:00+00:00"}`
2. Navigate to the `Application URL` (reload if it was already open, so the runs list refreshes)
3. **Verify** the "Runs" table contains a row whose ADW column is `e2e00002` (wait up to 20 seconds; the dashboard polls every 15 seconds)
4. Take a screenshot of the runs table with the seeded run
5. Click the `e2e00002` row
6. **Verify** a detail drawer opens with the heading `e2e00002`
7. **Verify** the drawer shows the sections "Budget", "Phase timeline", "Gates", and "Events (1)"
8. **Verify** the phase timeline lists `plan` as passed and `build` as failed
9. **Verify** the events list contains "plan passed"
10. **Verify** the budget section shows numeric values (no `NaN` or `undefined`)
11. Take a screenshot of the run detail drawer
12. Close the drawer (close button or click outside it)
13. **Verify** the drawer is closed and the runs table is visible
14. Clean up: delete `agent/runs/e2e00002/state.json` and `agent/runs/e2e00002/events.jsonl` with a plain `rm <file>` (no `-r`/`-f`), then `rmdir agent/runs/e2e00002`

## Success Criteria
- The seeded run appears in the runs table
- Clicking it opens a drawer for that exact run
- Budget, phase timeline, gates and events render with valid values
- Closing the drawer returns to the dashboard
- 2 screenshots are taken
- The fixture is removed afterwards
