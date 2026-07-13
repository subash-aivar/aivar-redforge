/**
 * Security Operations live event stream client — M15.
 *
 * Authentication decision: a native browser `EventSource` cannot set
 * an `Authorization` header, and this codebase has no cookie-based
 * session mechanism to lean on instead (see api.ts — bearer-header-only
 * everywhere). Rather than add a new auth surface (a stream-ticket
 * endpoint, or cookies), this client reads the `text/event-stream` wire
 * format itself over a `fetch()` `ReadableStream`, sending the exact
 * same `Authorization: Bearer` header every other request already
 * uses — zero new backend auth surface. The JWT is never placed in a
 * URL or query string.
 *
 * Resume: the last delivered event's `cursor` is sent back as the
 * `Last-Event-ID` header on reconnect — the backend resumes strictly
 * after it (see stream_service.py's own docstring for the composite
 * cursor format and malformed-cursor behavior).
 */
"use client";

import { useEffect, useRef, useState } from "react";
import { getApiBase, getAuthHeader } from "./api";
import type { OperationalEvent } from "./securityOperations";

export type StreamConnectionState = "connected" | "reconnecting" | "disconnected";

export interface SecurityOperationsStreamResult {
  connectionState: StreamConnectionState;
  events: OperationalEvent[];
  lastEventReceivedAt: string | null;
}

const MAX_BUFFER = 200;
const INITIAL_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;

function parseSseBlock(block: string): { id?: string; data?: string; isHeartbeat: boolean } {
  let id: string | undefined;
  let data: string | undefined;
  let isHeartbeat = false;
  for (const line of block.split("\n")) {
    if (line.startsWith("id: ")) id = line.slice(4);
    else if (line.startsWith("data: ")) data = line.slice(6);
    else if (line.startsWith(":")) isHeartbeat = true;
  }
  return { id, data, isHeartbeat };
}

export function useSecurityOperationsStream(enabled: boolean): SecurityOperationsStreamResult {
  const [connectionState, setConnectionState] = useState<StreamConnectionState>("disconnected");
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [lastEventReceivedAt, setLastEventReceivedAt] = useState<string | null>(null);

  const cursorRef = useRef<string | null>(null);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const abortRef = useRef<AbortController | null>(null);
  const reconnectDelayRef = useRef(INITIAL_RECONNECT_DELAY_MS);
  const stoppedRef = useRef(false);

  useEffect(() => {
    if (!enabled) return;
    stoppedRef.current = false;

    async function connectOnce(): Promise<void> {
      const controller = new AbortController();
      abortRef.current = controller;
      const headers: Record<string, string> = { ...getAuthHeader() };
      if (cursorRef.current) headers["Last-Event-ID"] = cursorRef.current;

      let response: Response;
      try {
        response = await fetch(`${getApiBase()}/api/v1/security-operations/events/stream`, {
          headers,
          signal: controller.signal,
        });
      } catch {
        throw new Error("stream connection failed");
      }
      if (!response.ok || !response.body) {
        throw new Error(`stream connection failed: ${response.status}`);
      }

      setConnectionState("connected");
      reconnectDelayRef.current = INITIAL_RECONNECT_DELAY_MS;

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let sepIndex: number;
        while ((sepIndex = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, sepIndex);
          buffer = buffer.slice(sepIndex + 2);
          const { id, data, isHeartbeat } = parseSseBlock(block);
          if (isHeartbeat) {
            setLastEventReceivedAt(new Date().toISOString());
            continue;
          }
          if (!data || !id) continue;
          if (seenIdsRef.current.has(id)) continue;
          try {
            const parsed = JSON.parse(data) as OperationalEvent;
            seenIdsRef.current.add(id);
            cursorRef.current = id;
            setLastEventReceivedAt(new Date().toISOString());
            setEvents((prev) => {
              const next = [...prev, parsed];
              if (next.length > MAX_BUFFER) {
                const dropped = next.splice(0, next.length - MAX_BUFFER);
                // seenIdsRef is keyed by the SSE frame id (== cursor), not
                // event_id — deleting by the wrong key left it unbounded.
                for (const d of dropped) seenIdsRef.current.delete(d.cursor);
              }
              return next;
            });
          } catch {
            // Malformed frame — skip rather than crash the stream.
            continue;
          }
        }
      }
    }

    async function loop(): Promise<void> {
      while (!stoppedRef.current) {
        try {
          await connectOnce();
          if (stoppedRef.current) return;
          setConnectionState("reconnecting");
        } catch {
          if (stoppedRef.current) return;
          setConnectionState("reconnecting");
        }
        await new Promise((resolve) => setTimeout(resolve, reconnectDelayRef.current));
        reconnectDelayRef.current = Math.min(
          reconnectDelayRef.current * 2,
          MAX_RECONNECT_DELAY_MS
        );
      }
    }

    void loop();

    return () => {
      stoppedRef.current = true;
      abortRef.current?.abort();
      setConnectionState("disconnected");
    };
  }, [enabled]);

  return { connectionState, events, lastEventReceivedAt };
}
