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

/** Live event feed, newest first. Controls are created once so re-renders never steal focus.
 * Renders at most once per animation frame; new events are prepended unless the filters changed. */
export class TimelineView {
  readonly el: HTMLElement;
  private events: DashEvent[] = [];
  private buffer: DashEvent[] = [];
  private fresh: DashEvent[] = [];
  private floor = 0;
  private paused = false;
  private rebuild = true;
  private renderedFilter = "";
  private frame = 0;
  private readonly adwSel = h("select", { attrs: { "aria-label": "Filter by adw_id" } });
  private readonly typeSel = h("select", { attrs: { "aria-label": "Filter by event type" } });
  private readonly pauseBtn = h("button", { class: "btn" }, "Pause");
  private readonly list = h("div", { class: "events-wrap" });

  constructor() {
    this.adwSel.addEventListener("change", () => this.schedule());
    this.typeSel.addEventListener("change", () => this.schedule());
    this.pauseBtn.addEventListener("click", () => this.togglePause());
    this.el = h(
      "section",
      { class: "panel timeline-panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Live events"), h("div", { class: "controls" }, this.adwSel, this.typeSel, this.pauseBtn)),
      this.list,
    );
    this.render();
  }

  /** The server snapshot. Live events with an id at or below its newest were already in it. */
  setInitial(events: DashEvent[]): void {
    this.events = [...events].sort((a, b) => b.id - a.id).slice(0, MAX_EVENTS);
    this.floor = this.events[0]?.id ?? 0;
    this.buffer = [];
    this.fresh = [];
    this.rebuild = true;
    this.schedule();
  }

  push(e: DashEvent): void {
    if (e.id <= this.floor) return;
    if (this.paused) {
      this.buffer.unshift(e);
      this.updatePauseLabel();
      return;
    }
    this.events.unshift(e);
    this.events.length = Math.min(this.events.length, MAX_EVENTS);
    this.addFresh([e]);
    this.schedule();
  }

  private togglePause(): void {
    this.paused = !this.paused;
    if (!this.paused && this.buffer.length) {
      this.events = [...this.buffer, ...this.events].slice(0, MAX_EVENTS);
      this.addFresh([...this.buffer].reverse());
      this.buffer = [];
    }
    this.updatePauseLabel();
    this.schedule();
  }

  /** Oldest first. Past a screenful a rebuild is cheaper than tracking them (e.g. a hidden tab gets no frames). */
  private addFresh(events: DashEvent[]): void {
    if (this.rebuild) return;
    this.fresh.push(...events);
    if (this.fresh.length > MAX_RENDERED) {
      this.fresh = [];
      this.rebuild = true;
    }
  }

  private schedule(): void {
    if (this.frame) return;
    this.frame = window.requestAnimationFrame(() => {
      this.frame = 0;
      this.render();
    });
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
    const filter = `${adw}\n${type}`;
    const matches = (e: DashEvent): boolean => (!adw || e.adw_id === adw) && (!type || e.event_type === type);
    const ul = this.list.firstElementChild;
    if (!this.rebuild && filter === this.renderedFilter && ul instanceof HTMLUListElement) {
      const rows = this.fresh.filter(matches).map(row).reverse();
      if (rows.length) {
        ul.prepend(...rows);
        while (ul.childElementCount > MAX_RENDERED) ul.lastElementChild?.remove();
      }
    } else {
      const shown = this.events.filter(matches);
      this.list.replaceChildren(
        shown.length
          ? h("ul", { class: "events" }, ...shown.slice(0, MAX_RENDERED).map(row))
          : empty("No events yet. ADWs POST to /api/events when TAC_DASHBOARD_URL is set."),
      );
    }
    this.fresh = [];
    this.rebuild = false;
    this.renderedFilter = filter;
  }
}
