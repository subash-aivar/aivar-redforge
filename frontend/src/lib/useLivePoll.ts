"use client";

import { useEffect, useRef } from "react";

/**
 * Global Live Operations Platform — centralized polling.
 *
 * Repository audit (this slice) found 11 pages independently
 * hand-rolling the identical `useEffect(() => { load(); const iv =
 * setInterval(load, N); return () => clearInterval(iv); }, [load])`
 * pattern (`security-operations`, `ddos` + 3 sub-pages, `behavior`,
 * `credential-vault`, `validation-operations`, `security-operations/
 * executions/[id]`, `platform/threat-intel/feeds/new`) — real,
 * measurable duplication, not hypothetical. This hook is the one
 * place that pattern now lives; each page keeps its own interval
 * duration (freshness needs genuinely differ — a 2s execution poll
 * vs. a 30s incident poll — so the interval itself is a parameter,
 * never hardcoded here).
 *
 * This is plain interval polling, NOT a second live-streaming
 * mechanism — the one real SSE stream in this app is still exclusively
 * `useSecurityOperationsStream`/`EventBusProvider`. Nothing here opens
 * a connection of any kind.
 */
export function useLivePoll(fn: () => void, intervalMs: number, enabled = true): void {
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    if (!enabled) return;
    fnRef.current();
    const id = setInterval(() => fnRef.current(), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs, enabled]);
}
