import { h, usd } from "../dom";
import type { Budget, CacheStats, Kpis, RunSummary } from "../types";

function tile(label: string, value: string, sub?: string, kind = ""): HTMLElement {
  return h("div", { class: `tile ${kind}` }, h("div", { class: "tile-label" }, label), h("div", { class: "tile-value" }, value), sub ? h("div", { class: "tile-sub" }, sub) : null);
}

function num(n: number | null | undefined, digits = 0): string {
  return typeof n === "number" ? n.toFixed(digits) : "—";
}

export function renderKpis(
  kpis: Kpis | null,
  budget: Budget | null,
  runs: RunSummary[],
  cache: CacheStats | null,
): HTMLElement {
  const hl = kpis?.highlights ?? {};
  let passed = 0;
  let total = 0;
  for (const r of runs) {
    passed += r.gates.passed;
    total += r.gates.passed + r.gates.failed + r.gates.error;
  }
  const rate = total ? Math.round((passed / total) * 100) : null;
  const t = budget?.totals;
  return h(
    "div",
    { class: "tiles" },
    tile("Current streak", num(hl.current_streak), hl.longest_streak != null ? `longest ${num(hl.longest_streak)}` : kpis?.exists ? "" : "no KPI file"),
    tile("Avg attempts", num(hl.average_attempts, 2), `presence ${num(hl.average_presence, 2)}`),
    tile("Total cost", usd(t?.cost_usd), t ? `${t.runs} runs · ${t.over_budget} over budget` : "", t && t.over_budget > 0 ? "bad" : ""),
    tile("Gate pass rate", rate === null ? "—" : `${rate}%`, `${passed}/${total} gates`, rate !== null && rate < 70 ? "warn" : ""),
    tile("Cache hits", cache ? String(cache.hits) : "—", cache?.exists ? `${cache.entries} entries` : "no cache.db"),
  );
}
