"use client";

import { Radio, WifiOff } from "lucide-react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState } from "@/design-system/primitives/States";
import { SeverityBadge } from "@/design-system/primitives/SeverityBadge";
import type { Severity } from "@/design-system/tokens";
import { usePlatformEventBus } from "@/components/platform/EventBusProvider";
import type { StreamConnectionState } from "@/lib/useSecurityOperationsStream";
import type { OperationalImportance } from "@/lib/securityOperations";

/** `OperationalImportance` (the SSE stream's own closed enum) ->
 * `Severity` (the design system's badge vocabulary). Two different
 * bounded contexts, two different vocabularies — mapped once, here,
 * rather than reimplemented per-consumer. */
function importanceToSeverity(importance: OperationalImportance): Severity {
  switch (importance) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "warning":
      return "medium";
    case "notice":
      return "low";
    case "info":
    default:
      return "informational";
  }
}

function ConnectionIndicator({ state }: { state: StreamConnectionState }) {
  if (state === "connected") {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-green-400">
        <Radio className="h-3 w-3 animate-pulse" aria-hidden="true" />
        Live
      </span>
    );
  }
  if (state === "reconnecting") {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-yellow-400">
        <WifiOff className="h-3 w-3" aria-hidden="true" />
        Reconnecting…
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs text-gray-500">
      <WifiOff className="h-3 w-3" aria-hidden="true" />
      Disconnected
    </span>
  );
}

export interface LiveFeedWidgetProps {
  title?: string;
  /** Cap on rendered rows — the underlying stream hook already caps its
   * internal buffer at 200; this is a display-only truncation. */
  maxEntries?: number;
}

/**
 * Reusable live security-events feed.
 *
 * The ONLY live-data widget in the framework, and it reads the
 * platform's one real streaming backbone (`useSecurityOperationsStream`,
 * M15 SSE) via the shared `EventBusProvider` context — never opens its
 * own second connection. (A prior version called the stream hook
 * directly, which — combined with `command-center/page.tsx` doing the
 * same — meant up to 3 independent, competing SSE connections per tab,
 * each running its own reconnect loop; that duplication is exactly what
 * `EventBusProvider` was built to prevent and is the root cause of a
 * real, observed reconnect storm.) No fabricated events — if there's
 * nothing to show, it shows the real "no events yet" empty state.
 */
export function LiveFeedWidget({
  title = "Live Security Feed",
  maxEntries = 15,
}: LiveFeedWidgetProps) {
  const { connectionState, events } = usePlatformEventBus();
  const visible = [...events].reverse().slice(0, maxEntries);

  return (
    <Card>
      <SectionHeader title={title} actions={<ConnectionIndicator state={connectionState} />} />
      <div className="mt-3">
        {visible.length === 0 ? (
          <EmptyState
            message={
              connectionState === "connected"
                ? "Connected. Waiting for the next platform event…"
                : "Connecting to the live event stream…"
            }
          />
        ) : (
          <ul className="max-h-96 space-y-2 overflow-y-auto">
            {visible.map((event) => (
              <li
                key={event.event_id}
                className="flex items-start justify-between gap-2 rounded-lg border border-gray-800 px-3 py-2"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={importanceToSeverity(event.importance)} />
                    <span className="text-[10px] uppercase tracking-wider text-gray-600">
                      {event.source_domain}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate text-sm text-gray-200">{event.title}</p>
                  <p className="truncate text-xs text-gray-500">{event.summary}</p>
                </div>
                <span className="shrink-0 text-[10px] text-gray-500">
                  {new Date(event.occurred_at).toLocaleTimeString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
