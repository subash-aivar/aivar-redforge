import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState } from "@/design-system/primitives/States";
import { SeverityBadge } from "@/design-system/primitives/SeverityBadge";
import type { Severity } from "@/design-system/tokens";

export interface TimelineEntry {
  id: string;
  timestamp: string;
  title: string;
  summary?: string;
  severity?: Severity;
  sourceLabel?: string;
}

export interface TimelineViewModel {
  id: string;
  title: string;
  entries: TimelineEntry[];
  emptyMessage?: string;
  maxEntries?: number;
}

/** Reusable chronological timeline — used for attack timelines,
 * change feeds, and live event history. Purely presentational: takes
 * already-ordered entries, never fetches or orders data itself. */
export function TimelineWidget({
  title,
  entries,
  emptyMessage = "No events in the selected range.",
  maxEntries = 20,
}: TimelineViewModel) {
  const visible = entries.slice(0, maxEntries);
  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {visible.length === 0 ? (
          <EmptyState message={emptyMessage} />
        ) : (
          <ol className="relative space-y-4 border-l border-gray-800 pl-4">
            {visible.map((entry) => (
              <li key={entry.id} className="relative">
                <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-gray-900 bg-gray-600" />
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-gray-500">
                    {new Date(entry.timestamp).toLocaleString()}
                  </span>
                  {entry.severity && <SeverityBadge severity={entry.severity} />}
                </div>
                <p className="mt-0.5 text-sm font-medium text-gray-200">{entry.title}</p>
                {entry.summary && <p className="text-xs text-gray-500">{entry.summary}</p>}
                {entry.sourceLabel && (
                  <span className="mt-0.5 inline-block text-[10px] uppercase tracking-wider text-gray-600">
                    {entry.sourceLabel}
                  </span>
                )}
              </li>
            ))}
          </ol>
        )}
      </div>
    </Card>
  );
}
