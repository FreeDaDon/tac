import { empty, fmtTime, h, pill, statusClass } from "../dom";
import type { RunDetail, RunEvent } from "../types";
import { budgetBar } from "./runs";

function eventItem(e: RunEvent): HTMLElement {
  return h(
    "li",
    { class: "ev" },
    h("span", { class: "ev-time muted" }, fmtTime(e.timestamp)),
    pill(e.event_type ?? "?", statusClass(e.event_type === "error" ? "error" : "")),
    e.phase ? h("span", { class: "ev-phase" }, e.phase) : null,
    h("span", { class: "ev-msg" }, e.message ?? ""),
  );
}

export function renderDrawer(detail: RunDetail | null, error: string | null, onClose: () => void): HTMLElement {
  const close = h("button", { class: "icon-btn", title: "Close (Esc)", onClick: onClose, attrs: { "aria-label": "Close" } }, "✕");
  if (error) return h("aside", { class: "drawer open" }, h("div", { class: "drawer-head" }, h("h2", {}, "Run"), close), empty(error));
  if (!detail) return h("aside", { class: "drawer open" }, h("div", { class: "drawer-head" }, h("h2", {}, "Loading…"), close));
  const s = detail.summary;
  const phases = Object.entries(s.phases);
  const gates = detail.gate_report?.gates ?? [];
  const events = [...detail.events].reverse();
  return h(
    "aside",
    { class: "drawer open", attrs: { role: "dialog", "aria-label": `Run ${s.adw_id}` } },
    h("div", { class: "drawer-head" }, h("h2", { class: "mono" }, s.adw_id), close),
    h("p", { class: "drawer-title" }, s.issue_number ? `#${s.issue_number} ` : "", s.issue_title ?? "(no issue title)"),
    h(
      "dl",
      { class: "meta" },
      ...([
        ["Domain", s.domain],
        ["Class", s.issue_class],
        ["Branch", s.branch_name],
        ["Model set", s.model_set],
        ["Attempts", String(s.attempts)],
        ["Ports", s.backend_port ? `${s.backend_port} / ${s.frontend_port ?? "—"}` : null],
        ["Created", fmtTime(s.created)],
        ["Updated", fmtTime(s.updated)],
      ] as const).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")]),
    ),
    s.error ? h("p", { class: "notice warn" }, s.error) : null,
    h("h3", {}, "Budget"),
    budgetBar(s.cost_usd, s.budget_usd),
    h("h3", {}, "Phase timeline"),
    phases.length
      ? h(
          "ol",
          { class: "timeline" },
          ...phases.map(([p, st]) => h("li", { class: `step ${statusClass(st)}` }, h("span", { class: "step-dot" }), h("span", {}, p), h("span", { class: "muted" }, st))),
        )
      : empty("No phases recorded."),
    h("h3", {}, "Gates"),
    gates.length
      ? h(
          "table",
          { class: "gates-table" },
          h("tbody", {}, ...gates.map((g) =>
            h(
              "tr",
              {},
              h("td", {}, g.name, g.required_for_zte ? null : h("span", { class: "muted", title: "not required for ZTE" }, " (opt)")),
              h("td", {}, pill(g.status, statusClass(g.status))),
              h("td", { class: "muted" }, g.duration_s ? `${g.duration_s.toFixed(1)}s` : ""),
              h("td", { class: "detail" }, g.detail),
            ),
          )),
        )
      : empty("No gate report."),
    h("h3", {}, `Events (${events.length})`),
    events.length ? h("ul", { class: "events compact" }, ...events.slice(0, 300).map(eventItem)) : empty("No events.jsonl entries."),
  );
}
