"use client";

import { useMemo, useState } from "react";
import { PageHeader } from "@/design-system/primitives/PageHeader";
import { ErrorState } from "@/design-system/primitives/States";
import { DashboardCompositionEngine } from "@/components/dashboard/layout/DashboardCompositionEngine";
import { WidgetLayoutEngine } from "@/components/dashboard/layout/WidgetLayoutEngine";
import { useDashboardAggregation } from "@/components/dashboard/aggregation/useDashboardAggregation";
import { socDashboardAggregator } from "@/components/dashboard/aggregation/socDashboardAggregator";
import { networkDashboardAggregator } from "@/components/dashboard/aggregation/networkDashboardAggregator";
import { TimeRangeSelector, type TimeRangeValue } from "@/components/dashboard/filters/TimeRangeSelector";
import { PlatformBootstrapCard } from "@/components/PlatformBootstrapCard";
import { NetworkQuickLinks } from "@/components/dashboard/NetworkQuickLinks";
import { getProductEdition } from "@/lib/productEdition";

/**
 * The platform's default landing dashboard — one page, one edition-aware
 * composition boundary. Which `DashboardAggregator` runs is the ONLY
 * edition-conditional decision in this file: `full` gets
 * `socDashboardAggregator` (unchanged from before this composition
 * split), `network_defense` gets `networkDashboardAggregator` (built
 * only from bounded contexts the Network Defense edition actually
 * mounts — see that module's own header comment). Neither aggregator
 * nor any widget below contains a second `if (edition)` branch — this
 * is deliberate: scattering edition checks through widgets would let
 * them drift out of sync with the backend's own `_Registration.editions`
 * source of truth. `getProductEdition()` throws for an unrecognized
 * build (see `lib/productEdition.ts`), so this call is also this page's
 * own defense-in-depth confirmation that the build is valid.
 */
export default function DashboardPage() {
  const isNetworkDefense = getProductEdition() === "network_defense";
  const [timeRange, setTimeRange] = useState<TimeRangeValue>("24h");
  const params = useMemo(() => ({ timeRange, filters: {} }), [timeRange]);
  const { spec, error, reload } = useDashboardAggregation(
    isNetworkDefense ? networkDashboardAggregator : socDashboardAggregator,
    params
  );

  return (
    <div>
      <PageHeader
        title={isNetworkDefense ? "Network Defense Overview" : "Security Operations Command Center"}
        subtitle={
          isNetworkDefense
            ? "Live network security posture"
            : "Live platform-wide security posture"
        }
        actions={<TimeRangeSelector value={timeRange} onChange={setTimeRange} />}
      />

      {error && (
        <div className="mt-4">
          <ErrorState message={error} onRetry={reload} />
        </div>
      )}

      {isNetworkDefense ? (
        <div className="mt-4">
          <NetworkQuickLinks />
        </div>
      ) : (
        <PlatformBootstrapCard />
      )}

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
