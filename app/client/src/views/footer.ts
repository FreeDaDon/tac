import { h } from "../dom";
import type { Version } from "../types";

export function renderFooter(version: Version | null): HTMLElement {
  return h(
    "footer",
    { class: "footer" },
    h("span", { class: "muted" }, version ? `${version.name} v${version.version}` : "…"),
  );
}
