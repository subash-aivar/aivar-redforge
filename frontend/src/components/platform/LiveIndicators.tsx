"use client";

/**
 * Global Live Operations Platform — shared presentational primitives.
 *
 * Pure UI utilities driven entirely by data the caller already has
 * (a timestamp, a connection state, a staleness flag) — none of these
 * fetch anything or open a connection themselves. Built to stop the
 * platform-wide pattern of every page hand-rolling its own
 * "Last event: {formatDateTime(x)}" string or its own connected/
 * reconnecting badge markup (already found duplicated across
 * `security-operations`, `GlobalStatusBar`, `NotificationCenter`
 * before this slice — each with a slightly different date format and
 * a slightly different pulse-dot markup).
 */
import { useEffect, useState } from "react";

/** Relative "Xs/Xm/Xh ago" that re-renders itself every second while
 * mounted — never a static string that silently goes stale on screen. */
export function RealtimeTimestamp({
  iso,
  prefix,
}: {
  iso: string | null;
  prefix?: string;
}) {
  const [, forceTick] = useState(0);

  useEffect(() => {
    if (!iso) return;
    const id = setInterval(() => forceTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [iso]);

  if (!iso) return <span className="text-gray-600">{prefix}never</span>;

  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const label =
    seconds < 5
      ? "just now"
      : seconds < 60
        ? `${seconds}s ago`
        : seconds < 3600
          ? `${Math.floor(seconds / 60)}m ago`
          : seconds < 86400
            ? `${Math.floor(seconds / 3600)}h ago`
            : new Date(iso).toLocaleDateString();

  return (
    <time dateTime={iso} title={new Date(iso).toLocaleString()} className="tabular-nums">
      {prefix}
      {label}
    </time>
  );
}

const CONNECTION_TONE: Record<string, string> = {
  connected: "text-emerald-400",
  live: "text-emerald-400",
  reconnecting: "text-amber-400",
  disconnected: "text-gray-500",
};

/** Same pulse-dot + label markup previously duplicated (with slightly
 * different classes each time) across `GlobalStatusBar` and
 * `security-operations`'s `ConnectionBadge` — now the one definition. */
export function ConnectionIndicator({
  state,
  labels,
}: {
  state: "connected" | "reconnecting" | "disconnected";
  /** Optional label overrides, e.g. { connected: "Live" }. */
  labels?: Partial<Record<"connected" | "reconnecting" | "disconnected", string>>;
}) {
  const tone = CONNECTION_TONE[state] ?? "text-gray-500";
  const label = labels?.[state] ?? state;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${tone}`}>
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          state === "connected" ? "animate-pulse bg-emerald-400" : state === "reconnecting" ? "bg-amber-500" : "bg-gray-600"
        }`}
        aria-hidden="true"
      />
      {label}
    </span>
  );
}

/** Flags data as stale once it's older than `thresholdMs` — never
 * animates or claims freshness it can't back up. */
export function StaleBadge({ iso, thresholdMs = 60_000 }: { iso: string | null; thresholdMs?: number }) {
  const [, forceTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => forceTick((n) => n + 1), 5000);
    return () => clearInterval(id);
  }, []);

  if (!iso) return null;
  const isStale = Date.now() - new Date(iso).getTime() > thresholdMs;
  if (!isStale) return null;

  return (
    <span
      className="rounded-full border border-amber-800 bg-amber-950/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300"
      role="status"
    >
      Stale
    </span>
  );
}
