# E2E Test: Live Events

Verify that an event POSTed to the API appears in the "Live events" timeline without a page reload.

## User Story

As a solo operator
I want agent events to show up in the live timeline as they happen
So that I can watch out-loop agents work without tailing log files

## Test Steps

1. Navigate to the `Application URL`
2. **Verify** the "Live events" panel is visible
3. **Verify** the live connection indicator in the header reports a connected state (wait up to 10 seconds)
4. **Verify** the timeline is not paused (the button reads "Pause", not "Resume")
5. Take a screenshot of the timeline before the event
6. Generate a unique marker: `e2e-live-<current unix time>`
7. Determine the API base URL: `http://127.0.0.1:<BACKEND_PORT>` using `BACKEND_PORT` from `.ports.env`, default `http://127.0.0.1:8000`
8. Send the event from the shell (do NOT reload the page). Use Python, because curl is denied by the project permission settings:
   `uv run python -c "import json,urllib.request as u; r=u.urlopen(u.Request('<API base URL>/api/events', data=json.dumps({'adw_id': 'e2e00001', 'event_type': 'phase_start', 'phase': 'test', 'message': '<marker>', 'source': 'e2e'}).encode(), headers={'Content-Type': 'application/json'}, method='POST'), timeout=5); print(r.status, r.read().decode())"`
   (If the API requires a token, the test fails with a clear error: the operator must run E2E without `TAC_DASHBOARD_TOKEN`. Never read `.env` to find it.)
9. **Verify** the response status is 201
10. **Verify** within 10 seconds, without reloading, a timeline entry containing the marker text appears
11. **Verify** the new entry shows the event type `phase_start` and the ADW ID `e2e00001`
12. Take a screenshot of the timeline showing the new event

## Success Criteria
- Timeline visible, connected and not paused before the event is sent
- POST /api/events returned 201
- The event appears in the timeline live, without a page reload
- The entry shows the marker text, event type and ADW ID
- 2 screenshots are taken
