"use client";

import { Bell, Pin, PinOff, WifiOff } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { SEVERITY_HEX, type Severity } from "@/design-system/tokens";
import { usePlatformEventBus } from "@/components/platform/EventBusProvider";
import { entityLink } from "@/lib/eventEntityLink";
import type { OperationalImportance } from "@/lib/securityOperations";

const SEVERITY_GROUPS: Severity[] = ["critical", "high", "medium", "low", "informational"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "System",
};

const PINNED_KEY = "redforge.notifications.pinned";
const MAX_PINNED = 50;

/** Same `OperationalImportance` -> `Severity` mapping used by
 * `LiveFeedWidget` — kept in one place rather than reimplemented per
 * consumer of the SSE stream. */
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
    default:
      return "informational";
  }
}


function readPinned(): Set<string> {
  try {
    const raw = window.localStorage?.getItem(PINNED_KEY);
    return raw ? new Set(JSON.parse(raw)) : new Set();
  } catch {
    return new Set();
  }
}

function writePinned(pinned: Set<string>) {
  try {
    window.localStorage?.setItem(PINNED_KEY, JSON.stringify([...pinned].slice(-MAX_PINNED)));
  } catch {
    // Storage unavailable — pinning degrades to session-only via React state.
  }
}

/**
 * Enterprise Notification Center.
 *
 * Backed exclusively by the real M15 Security Operations SSE stream
 * (via the shared `EventBusProvider` — no second connection) — no
 * synthetic notifications. Supports search, severity filtering,
 * pinning (persisted client-side; the backend has no per-notification
 * pin/ack/dismiss endpoint for this feed — confirmed by grep — so
 * this is honestly a local view preference, not a claim of durable
 * server-side state), and deep links to the owning module's real
 * detail page where one exists.
 *
 * Compliance/Cloud/AI/Red-Team-specific severity groupings are
 * intentionally NOT offered: none of those domains currently publish
 * into `platform_events` (confirmed against
 * `redforge.domain.security_operations.value_objects.SourceDomain`) —
 * each event's real `source_domain` is still shown per-row instead.
 */
export function NotificationCenter() {
  const { connectionState, events } = usePlatformEventBus();
  const [open, setOpen] = useState(false);
  const [readCount, setReadCount] = useState(0);
  const [query, setQuery] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set());
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setPinned(readPinned());
  }, []);

  const unread = Math.max(0, events.length - readCount);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function togglePin(eventId: string) {
    setPinned((prev) => {
      const next = new Set(prev);
      if (next.has(eventId)) next.delete(eventId);
      else next.add(eventId);
      writePinned(next);
      return next;
    });
  }

  function toggleSeverity(severity: Severity) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  }

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...events].reverse().filter((e) => {
      if (activeSeverities.size > 0 && !activeSeverities.has(importanceToSeverity(e.importance))) return false;
      if (q && !e.title.toLowerCase().includes(q) && !e.summary.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [events, query, activeSeverities]);

  const pinnedEntries = filtered.filter((e) => pinned.has(e.event_id));
  const grouped = SEVERITY_GROUPS.map((severity) => ({
    severity,
    entries: filtered.filter((e) => !pinned.has(e.event_id) && importanceToSeverity(e.importance) === severity),
  })).filter((g) => g.entries.length > 0);

  return (
    <div className="relative" ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => {
          setOpen((v) => !v);
          if (!open) setReadCount(events.length);
        }}
        aria-label={`Notifications${unread > 0 ? ` (${unread} unread)` : ""}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls="notification-center-panel"
        className="relative flex h-8 w-8 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200"
      >
        {connectionState === "connected" ? (
          <Bell className="h-4 w-4" aria-hidden="true" />
        ) : (
          <WifiOff className="h-4 w-4 text-gray-600" aria-hidden="true" />
        )}
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div
          id="notification-center-panel"
          role="dialog"
          aria-modal="false"
          aria-label="Notifications"
          className="absolute right-0 top-10 z-50 w-[26rem] rounded-xl border border-gray-800 bg-gray-900 shadow-2xl transition-all">
          <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
            <span className="text-sm font-semibold text-gray-200">Notifications</span>
            <span className="flex items-center gap-1.5 text-xs text-gray-500">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  connectionState === "connected" ? "animate-pulse bg-emerald-400" : "bg-amber-500"
                }`}
                aria-hidden="true"
              />
              {connectionState === "connected" ? "Live" : connectionState}
            </span>
          </div>

          <div className="space-y-2 border-b border-gray-800 px-4 py-2.5">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search notifications…"
              className="w-full rounded-md border border-gray-800 bg-gray-950/80 px-2.5 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
            />
            <div className="flex flex-wrap gap-1.5">
              {SEVERITY_GROUPS.map((severity) => (
                <button
                  key={severity}
                  type="button"
                  onClick={() => toggleSeverity(severity)}
                  className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide transition-colors ${
                    activeSeverities.has(severity)
                      ? "border-gray-500 bg-gray-700/60 text-gray-100"
                      : "border-gray-800 bg-gray-900/40 text-gray-500 hover:text-gray-300"
                  }`}
                  style={activeSeverities.has(severity) ? { borderColor: SEVERITY_HEX[severity] } : undefined}
                >
                  {SEVERITY_LABEL[severity]}
                </button>
              ))}
            </div>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {pinnedEntries.length === 0 && grouped.length === 0 ? (
              <p className="px-4 py-8 text-center text-sm text-gray-600">
                {events.length === 0
                  ? "No platform events yet. This panel updates in real time as they occur."
                  : "No notifications match this filter."}
              </p>
            ) : (
              <>
                {pinnedEntries.length > 0 && (
                  <div>
                    <div className="sticky top-0 bg-gray-900 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-amber-500">
                      Pinned ({pinnedEntries.length})
                    </div>
                    {pinnedEntries.map((entry) => (
                      <NotificationRow
                        key={entry.event_id}
                        entry={entry}
                        severity={importanceToSeverity(entry.importance)}
                        pinned
                        onTogglePin={() => togglePin(entry.event_id)}
                      />
                    ))}
                  </div>
                )}
                {grouped.map((group) => (
                  <div key={group.severity}>
                    <div className="sticky top-0 bg-gray-900 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                      {SEVERITY_LABEL[group.severity]} ({group.entries.length})
                    </div>
                    {group.entries.slice(0, 10).map((entry) => (
                      <NotificationRow
                        key={entry.event_id}
                        entry={entry}
                        severity={group.severity}
                        pinned={false}
                        onTogglePin={() => togglePin(entry.event_id)}
                      />
                    ))}
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function NotificationRow({
  entry,
  severity,
  pinned,
  onTogglePin,
}: {
  entry: import("@/lib/securityOperations").OperationalEvent;
  severity: Severity;
  pinned: boolean;
  onTogglePin: () => void;
}) {
  const href = entityLink(entry.entity_type, entry.entity_id);
  return (
    <div className="group border-t border-gray-800/50 px-4 py-2 transition-colors hover:bg-gray-800/30">
      <div className="flex items-center gap-2">
        <span
          className="h-1.5 w-1.5 shrink-0 rounded-full"
          style={{ backgroundColor: SEVERITY_HEX[severity] }}
          aria-hidden="true"
        />
        <span className="flex-1 truncate text-sm text-gray-200">{entry.title}</span>
        <button
          type="button"
          onClick={onTogglePin}
          aria-label={pinned ? "Unpin notification" : "Pin notification"}
          className={`transition-opacity group-hover:opacity-100 ${pinned ? "opacity-100" : "opacity-0"}`}
        >
          {pinned ? (
            <PinOff className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          ) : (
            <Pin className="h-3.5 w-3.5 text-gray-600 hover:text-gray-300" aria-hidden="true" />
          )}
        </button>
      </div>
      <p className="ml-3.5 truncate text-xs text-gray-500">{entry.summary}</p>
      <div className="ml-3.5 mt-0.5 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wider text-gray-600">{entry.source_domain}</span>
        <div className="flex items-center gap-2">
          {href && (
            <Link href={href} className="text-[10px] font-medium text-red-400 hover:text-red-300">
              Open →
            </Link>
          )}
          <span className="text-[10px] text-gray-600">{new Date(entry.occurred_at).toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
}
