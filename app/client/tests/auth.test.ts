// @vitest-environment happy-dom
// @vitest-environment-options {"url": "http://127.0.0.1:8000/?token=s3cret&view=runs"}
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/api";
import { LiveSocket } from "../src/ws";

afterEach(() => {
  vi.unstubAllGlobals();
});

it("sends the token as a bearer header on GETs and strips it from the address bar", async () => {
  const fetchMock = vi.fn(async () => new Response("[]", { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  await api.runs();
  await api.lessons();
  expect(fetchMock).toHaveBeenCalledTimes(2);
  for (const [url, init] of fetchMock.mock.calls as unknown as [URL, RequestInit][]) {
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer s3cret");
    expect(String(url)).not.toContain("s3cret");
  }
  expect(window.location.search).toBe("?view=runs");
});

it("passes the WebSocket token as a subprotocol, never in the URL", () => {
  const opened: [string, unknown][] = [];
  class FakeWebSocket {
    constructor(url: string, protocols?: string[]) {
      opened.push([url, protocols]);
    }
    close(): void {}
  }
  vi.stubGlobal("WebSocket", FakeWebSocket);
  const socket = new LiveSocket({ token: "s3cret", onMessage: () => {}, onState: () => {} });
  socket.start();
  socket.stop();
  expect(opened).toEqual([["ws://127.0.0.1:8000/ws/events", ["bearer", "s3cret"]]]);
});
