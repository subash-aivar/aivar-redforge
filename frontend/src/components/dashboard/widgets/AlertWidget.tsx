import { AlertOctagon } from "lucide-react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState } from "@/design-system/primitives/States";
import { SEVERITY_HEX, type Severity } from "@/design-system/tokens";

export interface AlertEntry {
  id: string;
  title: string;
  detail?: string;
  severity: Severity;
  timestamp: string;
}

export interface AlertViewModel {
  id: string;
  title: string;
  alerts: AlertEntry[];
  emptyMessage?: string;
  maxAlerts?: number;
}

/** Reusable prioritized alert list — sorted by severity (critical
 * first) then recency, matching the priority ordering a SOC analyst
 * expects. Sorting happens here (a pure presentational concern), not
 * in the aggregation layer. */
export function AlertWidget({
  title,
  alerts,
  emptyMessage = "No active alerts.",
  maxAlerts = 10,
}: AlertViewModel) {
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const sorted = [...alerts]
    .sort((a, b) => order[a.severity] - order[b.severity] || b.timestamp.localeCompare(a.timestamp))
    .slice(0, maxAlerts);

  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {sorted.length === 0 ? (
          <EmptyState message={emptyMessage} />
        ) : (
          <ul className="space-y-2">
            {sorted.map((alert) => (
              <li
                key={alert.id}
                className="flex items-start gap-2 rounded-lg border border-gray-800 px-3 py-2"
              >
                <AlertOctagon
                  className="mt-0.5 h-4 w-4 shrink-0"
                  style={{ color: SEVERITY_HEX[alert.severity] }}
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-sm font-medium text-gray-200">{alert.title}</p>
                    <span className="shrink-0 text-[10px] text-gray-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  {alert.detail && <p className="truncate text-xs text-gray-500">{alert.detail}</p>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
