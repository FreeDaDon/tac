import type { WsMessage } from "./types";

export type ConnState = "connecting" | "open" | "closed";

export interface LiveSocketOptions {
  token: string | null;
  onMessage: (msg: WsMessage) => void;
  onState: (state: ConnState) => void;
}

/** WebSocket with exponential backoff reconnect (1s -> 30s, jittered). */
export class LiveSocket {
  private ws: WebSocket | null = null;
  private attempt = 0;
  private timer: number | undefined;
  private stopped = false;

  constructor(private readonly opts: LiveSocketOptions) {}

  start(): void {
    this.stopped = false;
    this.open();
  }

  stop(): void {
    this.stopped = true;
    window.clearTimeout(this.timer);
    this.ws?.close();
  }

  private url(): string {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = new URL(`${proto}//${window.location.host}/ws/events`);
    if (this.opts.token) url.searchParams.set("token", this.opts.token);
    return url.toString();
  }

  private open(): void {
    this.opts.onState("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url());
    } catch {
      this.schedule();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      this.attempt = 0;
      this.opts.onState("open");
    };
    ws.onmessage = (ev: MessageEvent<string>) => {
      let msg: unknown;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (isWsMessage(msg)) this.opts.onMessage(msg);
    };
    ws.onclose = () => {
      this.ws = null;
      this.opts.onState("closed");
      this.schedule();
    };
    ws.onerror = () => ws.close();
  }

  private schedule(): void {
    if (this.stopped) return;
    const base = Math.min(30_000, 1000 * 2 ** this.attempt);
    this.attempt += 1;
    this.timer = window.setTimeout(() => this.open(), base / 2 + Math.random() * (base / 2));
  }
}

function isWsMessage(value: unknown): value is WsMessage {
  if (typeof value !== "object" || value === null) return false;
  const v = value as { type?: unknown; data?: unknown };
  if (v.type === "initial") return Array.isArray(v.data);
  if (v.type === "event") return typeof v.data === "object" && v.data !== null;
  return false;
}
