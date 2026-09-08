import type { LucideIcon } from "lucide-react";
import { Card } from "@/design-system/primitives/Card";
import { SEVERITY_ACCENT_CLASSES, type Severity } from "@/design-system/tokens";

export interface KpiViewModel {
  id: string;
  label: string;
  value: number | string;
  sublabel?: string;
  /** Optional severity accent — reuses the exact same palette as
   * `SeverityBadge` so a "Critical Findings" KPI card and a
   * "critical" badge elsewhere on the same page always agree. */
  severity?: Severity;
  icon?: LucideIcon;
  /** Percent change vs. the previous period, if the aggregation layer
   * computed one. Rendered as +/-N% — never fabricated client-side.
   * `tone` is supplied by the caller (who knows whether "up" is good
   * or bad for this specific metric) rather than assumed here. */
  trend?: { direction: "up" | "down" | "flat"; percent: number; tone?: "positive" | "negative" };
}

/** Reusable KPI card — the widget-framework replacement for the
 * hand-rolled `MetricCard` in `dashboard/page.tsx`. Renders only from
 * a `KpiViewModel`, never a raw API response.
 *
 * Label/value typography matches `cc.tsx`'s `KpiTile`
 * (`text-xs font-medium uppercase tracking-wider text-gray-500` label,
 * `tabular-nums` value) — found drifted during the platform
 * consistency audit (sentence-case label, non-tabular value), which
 * made numbers visibly jump width as they updated on this page only. */
export function KpiCard({ label, value, sublabel, severity, icon: Icon, trend }: KpiViewModel) {
  const accent = severity ? SEVERITY_ACCENT_CLASSES[severity] : "border-gray-800";
  return (
    <Card accentClassName={accent}>
      <div className="flex items-start justify-between">
        <div className="text-3xl font-bold tabular-nums text-inherit">{value}</div>
        {Icon && <Icon className="h-5 w-5 opacity-70" aria-hidden="true" />}
      </div>
      <div className="mt-1 text-xs font-medium uppercase tracking-wider text-gray-500">{label}</div>
      <div className="flex items-center justify-between">
        {sublabel && <div className="text-xs text-gray-500">{sublabel}</div>}
        {trend && trend.direction !== "flat" && (
          <span
            className={`text-xs font-medium ${
              trend.tone === "positive"
                ? "text-emerald-400"
                : trend.tone === "negative"
                  ? "text-red-400"
                  : "text-gray-400"
            }`}
          >
            {trend.direction === "up" ? "+" : "-"}
            {trend.percent}%
          </span>
        )}
      </div>
    </Card>
  );
}
