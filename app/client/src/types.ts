export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

export interface DashEvent {
  id: number;
  adw_id: string;
  event_type: string;
  phase: string;
  message: string;
  data: Record<string, Json>;
  source: string;
  timestamp: string;
}

export interface Health {
  status: string;
  root: string;
  events: number;
  ws_clients: number;
  auth_required: boolean;
}

export interface GatesSummary {
  passed: number;
  failed: number;
  skipped: number;
  error: number;
  total: number;
  all_green: boolean;
}

export interface RunSummary {
  adw_id: string;
  domain: string | null;
  issue_number: string | null;
  issue_title: string | null;
  issue_class: string | null;
  branch_name: string | null;
  model_set: string | null;
  phases: Record<string, string>;
  gates: GatesSummary;
  cost_usd: number;
  budget_usd: number;
  budget_fraction: number;
  attempts: number;
  workflows: string[];
  backend_port: number | null;
  frontend_port: number | null;
  created: string | null;
  updated: string | null;
  error: string | null;
}

export interface GateResult {
  name: string;
  status: "passed" | "failed" | "skipped" | "error";
  detail: string;
  duration_s: number;
  required_for_zte: boolean;
}

export interface GateReport {
  adw_id: string;
  created: string;
  gates: GateResult[];
}

export interface RunEvent {
  adw_id?: string;
  event_type?: string;
  phase?: string;
  message?: string;
  data?: Record<string, Json>;
  source?: string;
  timestamp?: string;
}

export interface RunDetail {
  summary: RunSummary;
  state: Record<string, Json> | null;
  gate_report: GateReport | null;
  events: RunEvent[];
}

export interface Kpis {
  exists: boolean;
  summary: Record<string, string>;
  tables: Record<string, Record<string, string>[]>;
  highlights: {
    current_streak?: number | null;
    longest_streak?: number | null;
    average_presence?: number | null;
    average_attempts?: number | null;
    runs_tracked?: number;
  };
}

export interface BudgetRow {
  adw_id: string;
  cost_usd: number;
  budget_usd: number;
  fraction: number;
  status: "ok" | "warn" | "over";
}

export interface Budget {
  runs: BudgetRow[];
  totals: { runs: number; cost_usd: number; budget_usd: number; over_budget: number; near_budget: number };
}

export interface Worktree {
  adw_id: string;
  backend_port: number | null;
  frontend_port: number | null;
  backend_live: boolean;
  frontend_live: boolean;
  has_ports_env: boolean;
  has_run: boolean;
}

export interface Lesson {
  file: string;
  name: string;
  description: string;
  tags: string[];
  body: string;
  updated: string;
}

export interface CacheStats {
  exists: boolean;
  entries: number;
  hits: number;
  by_command: { command: string; entries: number; hits: number }[];
  error?: string;
}

export type WsMessage = { type: "initial"; data: DashEvent[] } | { type: "event"; data: DashEvent };
