"use client";

import { useMemo } from "react";
import { PageHeader } from "@/design-system/primitives/PageHeader";
import { ErrorState } from "@/design-system/primitives/States";
import { DashboardCompositionEngine } from "@/components/dashboard/layout/DashboardCompositionEngine";
import { WidgetLayoutEngine } from "@/components/dashboard/layout/WidgetLayoutEngine";
import { useDashboardAggregation } from "@/components/dashboard/aggregation/useDashboardAggregation";
import { executiveAggregator } from "@/components/dashboard/aggregation/executiveAggregator";

/**
 * Executive (CISO) dashboard — the second persona built on the
 * Dashboard Aggregation Layer framework, proving it generalizes:
 * different aggregator, different KPIs (business/risk-framed, no
 * execution telemetry or DLQ noise), different chart set, same
 * reusable widget/composition/layout engines as the SOC dashboard.
 */
export default function ExecutiveDashboardPage() {
  const params = useMemo(() => ({ timeRange: "30d" as const, filters: {} }), []);
  const { spec, error, reload } = useDashboardAggregation(executiveAggregator, params);

  return (
    <div>
      <PageHeader
        title="Executive Security Posture"
        subtitle="Organizational risk, exposure, and compliance — business view"
      />

      {error && (
        <div className="mt-4">
          <ErrorState message={error} onRetry={reload} />
        </div>
      )}

      <div>
        {spec ? (
          <DashboardCompositionEngine {...spec} />
        ) : (
          <WidgetLayoutEngine
            slots={Array.from({ length: 6 }, (_, i) => ({
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
