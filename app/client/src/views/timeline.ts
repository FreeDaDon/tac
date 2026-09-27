import { empty, fmtTime, h, pill, statusClass } from "../dom";
import type { DashEvent } from "../types";

const MAX_EVENTS = 1000;
const MAX_RENDERED = 500;

function kindFor(e: DashEvent): string {
  if (e.event_type === "error") return "bad";
  if (e.event_type === "gate") {
    const st = e.data["status"];
    return typeof st === "string" ? statusClass(st) : "muted";
  }
  if (e.event_type === "budget") return "warn";
  if (e.event_type === "phase_end") return "ok";
  return "muted";
}

function syncOptions(select: HTMLSelectElement, label: string, values: string[]): void {
  const current = select.value;
  const wanted = ["", ...values];
  const existing = [...select.options].map((o) => o.value);
  if (existing.length === wanted.length && existing.every((v, i) => v === wanted[i])) return;
  select.replaceChildren(h("option", { attrs: { value: "" } }, label), ...values.map((v) => h("option", { attrs: { value: v } }, v)));
  select.value = values.includes(current) ? current : "";
}

function row(e: DashEvent): HTMLElement {
  return h(
    "li",
    { class: "ev", title: JSON.stringify(e.data).slice(0, 2000) },
    h("span", { class: "ev-time muted" }, fmtTime(e.timestamp)),
    h("span", { class: "mono ev-id" }, e.adw_id || "—"),
    pill(e.event_type, kindFor(e)),
    e.phase ? h("span", { class: "ev-phase" }, e.phase) : null,
    h("span", { class: "ev-msg" }, e.message),
    e.source && e.source !== "adw" ? h("span", { class: "muted ev-src" }, e.source) : null,
  );
}

/** Live event feed, newest first. Controls are created once so re-renders never steal focus. */
export class TimelineView {
  readonly el: HTMLElement;
  private events: DashEvent[] = [];
  private buffer: DashEvent[] = [];
  private paused = false;
  private readonly adwSel = h("select", { attrs: { "aria-label": "Filter by adw_id" } });
  private readonly typeSel = h("select", { attrs: { "aria-label": "Filter by event type" } });
  private readonly pauseBtn = h("button", { class: "btn" }, "Pause");
  private readonly list = h("div", { class: "events-wrap" });

  constructor() {
    this.adwSel.addEventListener("change", () => this.render());
    this.typeSel.addEventListener("change", () => this.render());
    this.pauseBtn.addEventListener("click", () => this.togglePause());
    this.el = h(
      "section",
      { class: "panel timeline-panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Live events"), h("div", { class: "controls" }, this.adwSel, this.typeSel, this.pauseBtn)),
      this.list,
    );
    this.render();
  }

  setInitial(events: DashEvent[]): void {
    this.events = [...events].sort((a, b) => b.id - a.id).slice(0, MAX_EVENTS);
    this.buffer = [];
    this.render();
  }

  push(e: DashEvent): void {
    if (this.paused) {
      this.buffer.unshift(e);
      this.updatePauseLabel();
      return;
    }
    this.events.unshift(e);
    this.events.length = Math.min(this.events.length, MAX_EVENTS);
    this.render();
  }

  private togglePause(): void {
    this.paused = !this.paused;
    if (!this.paused && this.buffer.length) {
      this.events = [...this.buffer, ...this.events].slice(0, MAX_EVENTS);
      this.buffer = [];
    }
    this.render();
  }

  private updatePauseLabel(): void {
    this.pauseBtn.textContent = this.paused ? `Resume${this.buffer.length ? ` (${this.buffer.length} new)` : ""}` : "Pause";
    this.pauseBtn.classList.toggle("active", this.paused);
  }

  private render(): void {
    syncOptions(this.adwSel, "all runs", [...new Set(this.events.map((e) => e.adw_id).filter(Boolean))].sort());
    syncOptions(this.typeSel, "all types", [...new Set(this.events.map((e) => e.event_type))].sort());
    this.updatePauseLabel();
    const adw = this.adwSel.value;
    const type = this.typeSel.value;
    const shown = this.events.filter((e) => (!adw || e.adw_id === adw) && (!type || e.event_type === type));
    this.list.replaceChildren(
      shown.length
        ? h("ul", { class: "events" }, ...shown.slice(0, MAX_RENDERED).map(row))
        : empty("No events yet. ADWs POST to /api/events when TAC_DASHBOARD_URL is set."),
    );
  }
}
