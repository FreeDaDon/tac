import "./style.css";
import { api, authToken } from "./api";
import { h } from "./dom";
import type { Budget, CacheStats, Health, Kpis, Lesson, RunDetail, RunSummary, Version, Worktree } from "./types";
import { renderDrawer } from "./views/drawer";
import { renderFooter } from "./views/footer";
import { renderHeader } from "./views/header";
import { renderKpis } from "./views/kpis";
import { renderLessons } from "./views/lessons";
import { renderRuns } from "./views/runs";
import { TimelineView } from "./views/timeline";
import { renderWorktrees } from "./views/worktrees";
import { type ConnState, LiveSocket } from "./ws";

const POLL_MS = 15_000;

interface AppState {
  health: Health | null;
  healthError: boolean;
  conn: ConnState;
  kpis: Kpis | null;
  budget: Budget | null;
  cache: CacheStats | null;
  runs: RunSummary[];
  worktrees: Worktree[];
  lessons: Lesson[];
  selected: string | null;
  detail: RunDetail | null;
  detailError: string | null;
  version: Version | null;
}

const state: AppState = {
  health: null, healthError: false, conn: "connecting", kpis: null, budget: null, cache: null,
  runs: [], worktrees: [], lessons: [], selected: null, detail: null, detailError: null, version: null,
};

const root = document.getElementById("app");
if (!root) throw new Error("#app missing");

const slots = {
  header: h("div"),
  kpis: h("div"),
  runs: h("div"),
  side: h("div", { class: "side" }),
  drawer: h("div"),
  footer: h("div"),
};
const timeline = new TimelineView();
root.append(
  slots.header,
  h(
    "main",
    { class: "layout" },
    slots.kpis,
    h("div", { class: "grid" }, h("div", { class: "main-col" }, slots.runs, timeline.el), slots.side),
  ),
  slots.drawer,
  slots.footer,
);

function renderAll(): void {
  slots.header.replaceChildren(renderHeader(state.health, state.healthError, state.conn));
  slots.kpis.replaceChildren(renderKpis(state.kpis, state.budget, state.runs, state.cache));
  slots.runs.replaceChildren(renderRuns(state.runs, state.selected, selectRun));
  slots.side.replaceChildren(renderWorktrees(state.worktrees), renderLessons(state.lessons));
  slots.footer.replaceChildren(renderFooter(state.version));
  renderDrawerSlot();
}

function renderDrawerSlot(): void {
  slots.drawer.replaceChildren(
    ...(state.selected
      ? [h("div", { class: "scrim", onClick: closeDrawer }), renderDrawer(state.detail, state.detailError, closeDrawer)]
      : []),
  );
}

async function settle<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch (err) {
    console.warn(err);
    return null;
  }
}

async function refresh(): Promise<void> {
  const [health, kpis, budget, cache, runs, worktrees, lessons] = await Promise.all([
    settle(api.health()), settle(api.kpis()), settle(api.budget()), settle(api.cache()),
    settle(api.runs()), settle(api.worktrees()), settle(api.lessons()),
  ]);
  state.health = health;
  state.healthError = health === null;
  state.kpis = kpis ?? state.kpis;
  state.budget = budget ?? state.budget;
  state.cache = cache ?? state.cache;
  state.runs = runs ?? state.runs;
  state.worktrees = worktrees ?? state.worktrees;
  state.lessons = lessons ?? state.lessons;
  renderAll();
  if (state.selected) void loadDetail(state.selected);
}

async function loadDetail(adwId: string): Promise<void> {
  try {
    const detail = await api.run(adwId);
    if (state.selected !== adwId) return;
    state.detail = detail;
    state.detailError = null;
  } catch (err) {
    if (state.selected !== adwId) return;
    state.detailError = err instanceof Error ? err.message : "failed to load run";
  }
  renderDrawerSlot();
}

function selectRun(adwId: string): void {
  state.selected = adwId;
  state.detail = null;
  state.detailError = null;
  renderAll();
  void loadDetail(adwId);
}

function closeDrawer(): void {
  state.selected = null;
  state.detail = null;
  renderAll();
}

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && state.selected) closeDrawer();
});

let refreshTimer: number | undefined;
function refreshSoon(): void {
  window.clearTimeout(refreshTimer);
  refreshTimer = window.setTimeout(() => void refresh(), 1500);
}

const socket = new LiveSocket({
  token: authToken(),
  onState: (conn) => {
    state.conn = conn;
    slots.header.replaceChildren(renderHeader(state.health, state.healthError, state.conn));
  },
  onMessage: (msg) => {
    if (msg.type === "initial") {
      timeline.setInitial(msg.data);
    } else {
      timeline.push(msg.data);
      refreshSoon(); // phase/gate/cost changes land in state.json; re-read it shortly
    }
  },
});

renderAll();
void refresh();
socket.start();
void settle(api.version()).then((v) => {
  state.version = v;
  slots.footer.replaceChildren(renderFooter(state.version));
});
window.setInterval(() => {
  if (document.visibilityState === "visible") void refresh();
}, POLL_MS);
