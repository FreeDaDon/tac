import { empty, fmtAgo, h, panel, pill } from "../dom";
import type { Lesson } from "../types";

export function renderLessons(lessons: Lesson[]): HTMLElement {
  if (!lessons.length) return panel("Lessons", empty("No lessons in agent/lessons/."));
  return panel(
    "Lessons",
    h(
      "div",
      { class: "lessons" },
      ...lessons.map((l) =>
        h(
          "details",
          { class: "lesson" },
          h(
            "summary",
            {},
            h("strong", {}, l.name),
            h("span", { class: "muted" }, ` · ${fmtAgo(l.updated)}`),
            l.description ? h("div", { class: "lesson-desc" }, l.description) : null,
            l.tags.length ? h("div", { class: "tags" }, ...l.tags.map((t) => pill(t, "muted"))) : null,
          ),
          h("pre", { class: "lesson-body" }, l.body),
        ),
      ),
    ),
  );
}
