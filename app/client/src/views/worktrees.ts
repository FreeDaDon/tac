import { empty, h, panel, pill } from "../dom";
import type { Worktree } from "../types";

function port(p: number | null, live: boolean): HTMLElement {
  if (!p) return h("span", { class: "muted" }, "—");
  return h("span", { class: "port" }, h("span", { class: `dot ${live ? "open" : "closed"}`, title: live ? "listening" : "not listening" }), String(p));
}

export function renderWorktrees(trees: Worktree[]): HTMLElement {
  if (!trees.length) return panel("Worktrees & ports", empty("No worktrees under trees/."));
  return panel(
    "Worktrees & ports",
    h(
      "table",
      { class: "compact-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "ADW"), h("th", {}, "Backend"), h("th", {}, "Frontend"), h("th", {}, ""))),
      h(
        "tbody",
        {},
        ...trees.map((t) =>
          h(
            "tr",
            {},
            h("td", { class: "mono" }, t.adw_id),
            h("td", {}, port(t.backend_port, t.backend_live)),
            h("td", {}, port(t.frontend_port, t.frontend_live)),
            h("td", {}, t.has_run ? null : pill("orphan", "warn", "no matching agent/runs entry"), t.has_ports_env ? null : pill("no .ports.env", "muted")),
          ),
        ),
      ),
    ),
  );
}
