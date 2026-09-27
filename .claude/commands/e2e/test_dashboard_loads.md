# E2E Test: Dashboard Loads

Verify the ADW Control Plane dashboard renders its KPI tiles and the runs table.

## User Story

As a solo operator running AI Developer Workflows
I want to open the dashboard and see agentic KPIs and recent runs at a glance
So that I know whether my agents are healthy without reading logs

## Test Steps

1. Navigate to the `Application URL`
2. Take a screenshot of the initial state
3. **Verify** the page title is "ADW Control Plane" and the header shows "Control Plane"
4. **Verify** the header API badge shows "API ok" (not "API down")
5. **Verify** the KPI area shows these tiles, each with a label and a value: "Current streak", "Avg attempts", "Total cost", "Gate pass rate", "Cache hits" (a value of "—" is acceptable when there is no data)
6. **Verify** no KPI tile value shows `NaN`, `undefined`, or `null`
7. Take a screenshot of the KPI tiles
8. **Verify** the "Runs" panel is present and shows EITHER a table with column headers "ADW", "Domain", "Issue", "Class", "Phases", "Gates", "Cost vs budget", "Updated" OR the empty state "No runs under agent/runs yet."
9. **Verify** there are no uncaught JavaScript errors in the browser console
10. Take a screenshot of the runs panel

## Success Criteria
- Page title is "ADW Control Plane" and the API badge is healthy
- All 5 KPI tiles render with valid values
- Runs panel renders a table with the expected headers, or the explicit empty state
- No uncaught console errors
- 3 screenshots are taken
