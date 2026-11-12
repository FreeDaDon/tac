// @vitest-environment happy-dom
import { beforeEach, expect, it, vi } from "vitest";
import type { DashEvent } from "../src/types";
import { TimelineView } from "../src/views/timeline";

let frames: FrameRequestCallback[] = [];

beforeEach(() => {
  frames = [];
  vi.spyOn(window, "requestAnimationFrame").mockImplementation((cb) => frames.push(cb));
});

function flush(): void {
  const pending = frames;
  frames = [];
  for (const cb of pending) cb(0);
}

function ev(id: number, adw_id = "a1b2c3d4", event_type = "gate"): DashEvent {
  return { id, adw_id, event_type, phase: "", message: `m${id}`, data: {}, source: "adw", timestamp: "2026-01-01T00:00:00Z" };
}

function messages(t: TimelineView): string[] {
  return [...t.el.querySelectorAll(".ev-msg")].map((n) => n.textContent ?? "");
}

it("renders a burst of events in one frame, newest first", () => {
  const t = new TimelineView();
  t.setInitial([ev(1)]);
  flush();
  t.push(ev(2));
  t.push(ev(3));
  t.push(ev(4));
  expect(messages(t)).toEqual(["m1"]);
  expect(frames).toHaveLength(1);
  flush();
  expect(messages(t)).toEqual(["m4", "m3", "m2", "m1"]);
});

it("prepends new rows without rebuilding the existing ones", () => {
  const t = new TimelineView();
  t.setInitial([ev(2), ev(1)]);
  flush();
  const before = [...t.el.querySelectorAll("li")];
  t.push(ev(3));
  flush();
  const after = [...t.el.querySelectorAll("li")];
  expect(after).toHaveLength(3);
  expect(after.slice(1)).toEqual(before);
  expect(after[1]).toBe(before[0]);
});

it("drops live events already covered by the snapshot", () => {
  const t = new TimelineView();
  t.setInitial([ev(5), ev(4)]);
  t.push(ev(5));
  t.push(ev(3));
  t.push(ev(6));
  flush();
  expect(messages(t)).toEqual(["m6", "m5", "m4"]);
});

it("rebuilds when a filter changes and keeps prepending under the filter", () => {
  const t = new TimelineView();
  t.setInitial([ev(2, "deadbeef"), ev(1)]);
  flush();
  const select = t.el.querySelector("select") as HTMLSelectElement;
  select.value = "deadbeef";
  select.dispatchEvent(new Event("change"));
  flush();
  expect(messages(t)).toEqual(["m2"]);
  t.push(ev(3));
  t.push(ev(4, "deadbeef"));
  flush();
  expect(messages(t)).toEqual(["m4", "m2"]);
});

it("shows at most 500 rows", () => {
  const t = new TimelineView();
  t.setInitial([ev(1)]);
  flush();
  for (let id = 2; id <= 700; id += 1) {
    t.push(ev(id));
    if (id % 50 === 0) flush();
  }
  flush();
  const shown = messages(t);
  expect(shown).toHaveLength(500);
  expect(shown[0]).toBe("m700");
});

it("keeps paused events out until resumed", () => {
  const t = new TimelineView();
  t.setInitial([ev(1)]);
  flush();
  const pause = t.el.querySelector("button") as HTMLButtonElement;
  pause.click();
  t.push(ev(2));
  t.push(ev(3));
  flush();
  expect(messages(t)).toEqual(["m1"]);
  expect(pause.textContent).toBe("Resume (2 new)");
  pause.click();
  flush();
  expect(messages(t)).toEqual(["m3", "m2", "m1"]);
});
