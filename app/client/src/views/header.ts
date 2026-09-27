import { h } from "../dom";
import type { Health } from "../types";
import type { ConnState } from "../ws";

export function renderHeader(health: Health | null, healthError: boolean, conn: ConnState): HTMLElement {
  const connLabel = conn === "open" ? "live" : conn === "connecting" ? "connecting" : "offline";
  return h(
    "header",
    { class: "topbar" },
    h("div", { class: "brand" }, h("span", { class: "logo" }, "ADW"), h("h1", {}, "Control Plane")),
    h(
      "div",
      { class: "status" },
      h(
        "span",
        { class: `badge ${healthError ? "bad" : health ? "ok" : "muted"}`, title: "GET /api/health" },
        healthError ? "API down" : health ? `API ok · ${health.events} events` : "API …",
      ),
      health?.auth_required ? h("span", { class: "badge muted", title: "Bearer token required for writes" }, "auth") : null,
      h(
        "span",
        { class: "conn", title: `WebSocket: ${conn}` },
        h("span", { class: `dot ${conn}` }),
        connLabel,
      ),
    ),
  );
}
