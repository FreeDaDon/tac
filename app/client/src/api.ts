import type {
  Budget, CacheStats, DashEvent, Health, Kpis, Lesson, RunDetail, RunSummary, Version, Worktree,
} from "./types";

const TOKEN_KEY = "tac-dashboard-token";

/** Optional bearer token: pass once as ?token=... ; kept in sessionStorage, stripped from the URL. */
export function authToken(): string | null {
  const url = new URL(window.location.href);
  const fromUrl = url.searchParams.get("token");
  try {
    if (fromUrl) {
      sessionStorage.setItem(TOKEN_KEY, fromUrl);
      url.searchParams.delete("token");
      window.history.replaceState(null, "", url.toString());
      return fromUrl;
    }
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return fromUrl;
  }
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  }
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText} for ${path}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => get<Health>("/api/health"),
  events: (opts: { limit?: number; adw_id?: string; event_type?: string } = {}) =>
    get<DashEvent[]>("/api/events", opts),
  filterOptions: () => get<Record<"adw_id" | "event_type" | "source", string[]>>("/api/events/filter-options"),
  runs: () => get<RunSummary[]>("/api/runs"),
  run: (adwId: string) => {
    if (!/^[a-f0-9]{8}$/.test(adwId)) return Promise.reject(new ApiError(400, "invalid adw_id"));
    return get<RunDetail>(`/api/runs/${adwId}`);
  },
  kpis: () => get<Kpis>("/api/kpis"),
  budget: () => get<Budget>("/api/budget"),
  worktrees: () => get<Worktree[]>("/api/worktrees"),
  lessons: () => get<Lesson[]>("/api/lessons"),
  cache: () => get<CacheStats>("/api/cache"),
  version: () => get<Version>("/api/version"),
};
