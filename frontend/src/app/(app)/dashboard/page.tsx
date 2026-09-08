"use client";

import { useMemo, useState } from "react";
import { PageHeader } from "@/design-system/primitives/PageHeader";
import { ErrorState } from "@/design-system/primitives/States";
import { DashboardCompositionEngine } from "@/components/dashboard/layout/DashboardCompositionEngine";
import { WidgetLayoutEngine } from "@/components/dashboard/layout/WidgetLayoutEngine";
import { useDashboardAggregation } from "@/components/dashboard/aggregation/useDashboardAggregation";
import { socDashboardAggregator } from "@/components/dashboard/aggregation/socDashboardAggregator";
import { TimeRangeSelector, type TimeRangeValue } from "@/components/dashboard/filters/TimeRangeSelector";
import { PlatformBootstrapCard } from "@/components/PlatformBootstrapCard";

/**
 * Security Operations Command Center — the platform's SOC dashboard.
 *
 * Every widget is composed from `socDashboardAggregator`'s output —
 * this page never calls a bounded-context API directly (see
 * `dashboard/aggregation/types.ts`'s architecture note). Loading is
 * intentionally non-blocking: the header renders synchronously on
 * first paint, and while the aggregation call is in flight this page
 * shows quiet skeleton placeholders rather than a literal "Loading…"
 * message — the shell is never gated behind a full-page loading
 * state (regression-tested by `page.test.tsx`).
 */
export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRangeValue>("24h");
  const params = useMemo(() => ({ timeRange, filters: {} }), [timeRange]);
  const { spec, error, reload } = useDashboardAggregation(socDashboardAggregator, params);

  return (
    <div>
      <PageHeader
        title="Security Operations Command Center"
        subtitle="Live platform-wide security posture"
        actions={<TimeRangeSelector value={timeRange} onChange={setTimeRange} />}
      />

      {error && (
        <div className="mt-4">
          <ErrorState message={error} onRetry={reload} />
        </div>
      )}

      <PlatformBootstrapCard />

      <div className="mt-6">
        {spec ? (
          <DashboardCompositionEngine {...spec} />
        ) : (
          <WidgetLayoutEngine
            slots={Array.from({ length: 8 }, (_, i) => ({
              key: `skeleton-${i}`,
              span: 1 as const,
              node: (
                <div
                  className="h-[104px] animate-pulse rounded-xl border border-gray-800 bg-gray-900"
                  aria-hidden="true"
                />
              ),
            }))}
          />
        )}
      </div>
    </div>
  );
}
