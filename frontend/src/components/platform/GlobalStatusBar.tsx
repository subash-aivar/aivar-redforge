"use client";

/**
 * Global Status Bar (Phase 4).
 *
 * Persistent strip answering "is the platform healthy, right now" from
 * two real sources only:
 *  - `GET /api/v1/runtime/status` (unauthenticated-by-design quick health
 *    check — see `redforge/api/v1/runtime.py`'s "Unauthenticated
 *    endpoints" section) for overall platform health / DLQ depth.
 *  - the shared `EventBusProvider` connection state for live-stream health.
 *
 * Deliberately does NOT show app version or environment: neither is
 * exposed anywhere in this frontend today (no `NEXT_PUBLIC_ENV`, no
 * runtime-exposed package version) — confirmed by grep before writing
 * this file. Inventing either would violate the no-fabrication rule, so
 * both are omitted rather than guessed.
 */
import { Activity, AlertTriangle, Wifi, WifiOff } from "lucide-react";
import { useEffect } from "react";
import { usePlatformEventBus } from "@/components/platform/EventBusProvider";
import { useAsync } from "@/components/cc";
import { getRuntimeStatus } from "@/lib/runtime";

const HEALTH_POLL_INTERVAL_MS = 30_000;

const HEALTH_TONE: Record<string, string> = {
  healthy: "text-emerald-400",
  degraded: "text-amber-400",
  unhealthy: "text-red-400",
};

export function GlobalStatusBar({ organizationName }: { organizationName?: string | null }) {
  const status = useAsync(() => getRuntimeStatus(), []);
  const { connectionState } = usePlatformEventBus();

  // `/runtime/status` is a plain polled endpoint, not part of the SSE
  // event bus — refresh it on a coarse interval so the bar doesn't go
  // stale silently, without opening any new connection type.
  useEffect(() => {
    const id = setInterval(() => status.reload(), HEALTH_POLL_INTERVAL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="flex h-7 shrink-0 items-center gap-4 border-b border-gray-900 bg-gray-950 px-6 text-[11px] text-gray-500">
      <div className="flex items-center gap-1.5">
        {connectionState === "connected" ? (
          <Wifi className="h-3 w-3 text-emerald-500" aria-hidden="true" />
        ) : (
          <WifiOff className="h-3 w-3 text-amber-500" aria-hidden="true" />
        )}
        <span>{connectionState === "connected" ? "Live" : connectionState}</span>
      </div>

      <div className="h-3 w-px bg-gray-800" aria-hidden="true" />

      {status.loading ? (
        <span className="text-gray-600">Checking platform health…</span>
      ) : status.error || status.forbidden || !status.data ? (
        <span className="text-gray-600">Platform health unavailable</span>
      ) : (
        <>
          <div className="flex items-center gap-1.5">
            <Activity
              className={`h-3 w-3 ${HEALTH_TONE[status.data.overall_health] ?? "text-gray-500"}`}
              aria-hidden="true"
            />
            <span className={HEALTH_TONE[status.data.overall_health] ?? "text-gray-400"}>
              {status.data.overall_health}
            </span>
            <span className="text-gray-700">
              ({status.data.component_count - status.data.unhealthy_components.length}/
              {status.data.component_count} components)
            </span>
          </div>

          {status.data.dlq_total_entries > 0 && (
            <div className="flex items-center gap-1.5 text-amber-400">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" />
              <span>{status.data.dlq_total_entries} DLQ entries</span>
            </div>
          )}
        </>
      )}

      {organizationName && (
        <>
          <div className="ml-auto h-3 w-px bg-gray-800" aria-hidden="true" />
          <span className="text-gray-600">{organizationName}</span>
        </>
      )}
    </div>
  );
}
