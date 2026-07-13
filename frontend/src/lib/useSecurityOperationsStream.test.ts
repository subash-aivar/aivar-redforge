import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook, waitFor, cleanup } from "@testing-library/react";
import { useSecurityOperationsStream } from "./useSecurityOperationsStream";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function sseBody(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let i = 0;
  return new ReadableStream({
    pull(controller) {
      if (i < chunks.length) {
        controller.enqueue(encoder.encode(chunks[i]));
        i += 1;
      } else {
        controller.close();
      }
    },
  });
}

function frame(id: string, event: object): string {
  return `id: ${id}\nevent: operational_event\ndata: ${JSON.stringify(event)}\n\n`;
}

function makeEvent(id: string, overrides: object = {}) {
  return {
    cursor: id,
    event_id: id,
    organization_id: "org-1",
    source_domain: "validation",
    importance: "info",
    title: "Validation started",
    summary: "Validation started.",
    entity_type: "validation_execution",
    entity_id: "exec-1",
    occurred_at: new Date(0).toISOString(),
    schema_version: 1,
    ...overrides,
  };
}

describe("useSecurityOperationsStream", () => {
  it("parses real SSE frames into events, in order", async () => {
    const body = sseBody([
      frame("c1", makeEvent("c1")),
      frame("c2", makeEvent("c2")),
    ]);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(body, { status: 200 }))
    );

    const { result } = renderHook(() => useSecurityOperationsStream(true));

    await waitFor(() => {
      expect(result.current.events.map((e) => e.event_id)).toEqual(["c1", "c2"]);
    });
    // connectionState may already have moved to "reconnecting" by this point
    // since this mock stream is intentionally finite (a real stream never
    // completes on its own) — connection-state truthfulness itself is
    // covered separately by the page-level ConnectionBadge tests.
  });

  it("deduplicates by event_id — never inserts the same event twice", async () => {
    const body = sseBody([frame("dup1", makeEvent("dup1")), frame("dup1", makeEvent("dup1"))]);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status: 200 })));

    const { result } = renderHook(() => useSecurityOperationsStream(true));

    await waitFor(() => {
      expect(result.current.events.length).toBeGreaterThan(0);
    });
    expect(result.current.events.filter((e) => e.event_id === "dup1")).toHaveLength(1);
  });

  it("ignores heartbeat comment lines — never fabricates an event from one", async () => {
    const body = sseBody([": heartbeat\n\n", frame("h1", makeEvent("h1"))]);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status: 200 })));

    const { result } = renderHook(() => useSecurityOperationsStream(true));

    await waitFor(() => {
      expect(result.current.events.map((e) => e.event_id)).toEqual(["h1"]);
    });
    expect(result.current.lastEventReceivedAt).not.toBeNull();
  });

  it("bounds its in-memory buffer rather than growing unbounded", async () => {
    const chunks = Array.from({ length: 250 }, (_, i) => frame(`e${i}`, makeEvent(`e${i}`)));
    const body = sseBody(chunks);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status: 200 })));

    const { result } = renderHook(() => useSecurityOperationsStream(true));

    await waitFor(() => {
      expect(result.current.events.length).toBeGreaterThan(0);
    });
    await waitFor(
      () => {
        expect(result.current.events.length).toBeLessThanOrEqual(200);
      },
      { timeout: 2000 }
    );
  });

  it("does not connect at all when disabled", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    renderHook(() => useSecurityOperationsStream(false));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("never places the JWT in the request URL", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(sseBody([]), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    renderHook(() => useSecurityOperationsStream(true));
    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalled();
    });
    const [url] = fetchSpy.mock.calls[0] as [string, unknown];
    expect(url).not.toMatch(/token|jwt|bearer/i);
  });
});
