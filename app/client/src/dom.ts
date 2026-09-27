/** Tiny DOM builder. All text goes through createTextNode/textContent — never innerHTML. */

type Child = Node | string | number | null | undefined | false;
type Props = {
  class?: string;
  title?: string;
  onClick?: (ev: Event) => void;
  attrs?: Record<string, string>;
  style?: Record<string, string>;
};

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props.class) el.className = props.class;
  if (props.title) el.title = props.title;
  if (props.onClick) el.addEventListener("click", props.onClick);
  for (const [k, v] of Object.entries(props.attrs ?? {})) {
    if (/^on/i.test(k)) continue; // event handlers only via addEventListener
    el.setAttribute(k, v);
  }
  for (const [k, v] of Object.entries(props.style ?? {})) el.style.setProperty(k, v);
  append(el, ...children);
  return el;
}

export function append(el: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}

export function clear(el: Element): void {
  el.replaceChildren();
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function usd(n: number | null | undefined): string {
  return typeof n === "number" ? `$${n.toFixed(n >= 100 ? 0 : 2)}` : "—";
}

export function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (["passed", "ok", "success", "done", "completed"].includes(s)) return "ok";
  if (["failed", "error", "over", "blocked"].includes(s)) return "bad";
  if (["running", "warn", "in_progress", "pending"].includes(s)) return "warn";
  return "muted";
}

export function pill(text: string, kind: string, title?: string): HTMLSpanElement {
  return h("span", { class: `pill ${kind}`, ...(title ? { title } : {}) }, text);
}

export function panel(title: string, ...children: Child[]): HTMLElement {
  return h("section", { class: "panel" }, h("h2", {}, title), ...children);
}

export function empty(text: string): HTMLElement {
  return h("p", { class: "empty" }, text);
}
