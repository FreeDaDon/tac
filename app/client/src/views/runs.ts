import { empty, fmtAgo, h, panel, pill, statusClass, usd } from "../dom";
import type { RunSummary } from "../types";

export function budgetBar(cost: number, budget: number): HTMLElement {
  const frac = budget > 0 ? cost / budget : 0;
  const kind = frac >= 1 ? "bad" : frac >= 0.8 ? "warn" : "ok";
  return h(
    "div",
    { class: "budget", title: `${usd(cost)} of ${usd(budget)} (${Math.round(frac * 100)}%)` },
    h("div", { class: "bar" }, h("div", { class: `fill ${kind}`, style: { width: `${Math.min(100, frac * 100).toFixed(1)}%` } })),
    h("span", { class: "budget-label" }, `${usd(cost)} / ${usd(budget)}`),
  );
}

function gatesCell(r: RunSummary): HTMLElement {
  const g = r.gates;
  if (!g.total) return h("span", { class: "muted" }, "—");
  return h(
    "span",
    { class: "gates" },
    g.all_green ? pill("ZTE ✓", "ok", "all required gates passed") : null,
    g.passed ? pill(`${g.passed} ✓`, "ok", "passed") : null,
    g.failed ? pill(`${g.failed} ✗`, "bad", "failed") : null,
    g.error ? pill(`${g.error} !`, "bad", "error") : null,
    g.skipped ? pill(`${g.skipped} –`, "muted", "skipped") : null,
  );
}

export function renderRuns(runs: RunSummary[], selected: string | null, onSelect: (id: string) => void): HTMLElement {
  if (!runs.length) return panel("Runs", empty("No runs under agent/runs yet."));
  const rows = runs.map((r) =>
    h(
      "tr",
      {
        class: `clickable${r.adw_id === selected ? " selected" : ""}`,
        onClick: () => onSelect(r.adw_id),
        attrs: { tabindex: "0" },
      },
      h("td", { class: "mono" }, r.adw_id, r.error ? h("span", { class: "warn-icon", title: r.error }, " ⚠") : null),
      h("td", {}, r.domain ?? "—"),
      h("td", { class: "issue", title: r.issue_title ?? "" }, r.issue_number ? `#${r.issue_number} ` : "", h("span", { class: "muted" }, r.issue_title ?? "")),
      h("td", {}, r.issue_class ?? "—"),
      h("td", { class: "phases" }, ...Object.entries(r.phases).map(([p, s]) => pill(p, statusClass(s), s))),
      h("td", {}, gatesCell(r)),
      h("td", {}, budgetBar(r.cost_usd, r.budget_usd)),
      h("td", { class: "muted nowrap", title: r.updated ?? "" }, fmtAgo(r.updated)),
    ),
  );
  for (const row of rows) {
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") row.click();
    });
  }
  return panel(
    "Runs",
    h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        { class: "runs" },
        h("thead", {}, h("tr", {}, ...["ADW", "Domain", "Issue", "Class", "Phases", "Gates", "Cost vs budget", "Updated"].map((c) => h("th", {}, c)))),
        h("tbody", {}, ...rows),
      ),
    ),
  );
}
