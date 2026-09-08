import * as exposureApi from "@/lib/exposure";
import * as riskEngine from "@/lib/riskEngine";
import * as complianceApi from "@/lib/compliance";
import * as aiPostureApi from "@/lib/ai-posture";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import type { Severity } from "@/design-system/tokens";
import type { DashboardAggregator } from "@/components/dashboard/aggregation/types";
import type { DashboardSpec, WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";
import type { KpiViewModel } from "@/components/dashboard/widgets/KpiCard";

async function settle<T>(promise: Promise<T>, fallback: T): Promise<T> {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

// Score band thresholds match the `/exposure` page's own `ScoreBadge`
// convention (0.0–10.0 scale, per ADR-M32-003 / exposure_score_formula.py)
// — a real per-asset score binned into ranges, not a fabricated severity.
function binExposureScores(scores: number[]): { name: Severity; value: number }[] {
  const bands: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const score of scores) {
    if (score >= 8.0) bands.critical += 1;
    else if (score >= 6.0) bands.high += 1;
    else if (score >= 4.0) bands.medium += 1;
    else bands.low += 1;
  }
  return (Object.entries(bands) as [Severity, number][]).filter(([, value]) => value > 0).map(([name, value]) => ({ name, value }));
}

/**
 * Executive (CISO) dashboard aggregator.
 *
 * Deliberately narrower and business-framed compared to
 * `socDashboardAggregator`: no execution telemetry, no DLQ, no
 * circuit breakers, no per-detection noise — only organizational
 * risk/exposure/compliance/AI posture, exactly what the platform-
 * realization brief asked for ("no engineering noise"). Every value
 * still traces to a real endpoint; this is a different *view* over
 * real data, not a different data-integrity standard.
 */
export const executiveAggregator: DashboardAggregator = {
  id: "executive-overview",
  async load(): Promise<DashboardSpec> {
    const [exposure, riskProfiles, complianceProfiles, aiInventory, assets] = await Promise.all([
      settle(exposureApi.getExposureProfile(), null),
      settle(riskEngine.listRiskProfiles({ limit: 100 }), { items: [], count: 0 }),
      settle(complianceApi.listProfiles(), []),
      settle(aiPostureApi.getInventoryDashboard(), null),
      settle(attackSurfaceManagement.listAssets({ limit: 200 }), { items: [], count: 0 }),
    ]);

    const acceptedRiskCount = riskProfiles.items.filter((p) => p.status === "accepted").length;
    const openRiskCount = riskProfiles.items.filter((p) => p.status !== "accepted").length;
    const avgComposite =
      riskProfiles.items.length > 0
        ? riskProfiles.items.reduce((sum, p) => sum + (p.composite_score ?? 0), 0) /
          riskProfiles.items.length
        : null;

    const kpis: KpiViewModel[] = [
      {
        id: "avg-exposure-score",
        label: "Tenant Exposure Score",
        value: exposure ? exposure.tenant_exposure_score.toFixed(1) : "—",
        sublabel: exposure
          ? `${Object.keys(exposure.asset_scores).length} assets scored`
          : "No exposure data yet",
      },
      {
        id: "avg-risk-score",
        label: "Average Risk Score",
        value: avgComposite !== null ? avgComposite.toFixed(2) : "—",
        sublabel: `${riskProfiles.count} enterprise risk profiles`,
      },
      {
        id: "open-risk",
        label: "Open Risk Profiles",
        value: openRiskCount,
        sublabel: "Requiring disposition",
        severity: openRiskCount > 0 ? "medium" : undefined,
      },
      {
        id: "accepted-risk",
        label: "Accepted Risk",
        value: acceptedRiskCount,
        sublabel: "Formally risk-accepted",
      },
      {
        id: "compliance-frameworks",
        label: "Compliance Programs",
        value: complianceProfiles.length,
        sublabel: "Active compliance profiles",
      },
      {
        id: "attack-surface-assets",
        label: "Attack Surface Size",
        value: assets.count,
        sublabel: "Discovered organizational assets",
      },
    ];

    if (aiInventory) {
      kpis.push({
        id: "ai-assets",
        label: "AI Systems Inventoried",
        value: aiInventory.assets.length,
        sublabel: aiInventory.coverage_scope,
      });
    }

    // `ExposureProfileDTO` (backend/src/exposure/application/dtos/
    // exposure_dtos.py) only carries per-asset scores and their average —
    // no severity-bucket breakdown exists in this domain. A distribution
    // is built from the real per-asset scores themselves (binned into
    // score ranges), not a fabricated critical/high/medium/low split.
    const exposureDistributionOption =
      exposure && Object.keys(exposure.asset_scores).length > 0
        ? {
            tooltip: { trigger: "item" as const },
            legend: { top: "bottom", textStyle: { color: "#9ca3af", fontSize: 10 } },
            series: [
              {
                type: "pie" as const,
                radius: ["45%", "70%"],
                itemStyle: { borderColor: "#111827", borderWidth: 2 },
                label: { color: "#d1d5db" },
                data: binExposureScores(Object.values(exposure.asset_scores)),
              },
            ],
          }
        : null;

    const criticalityBreakdown = new Map<string, number>();
    for (const asset of assets.items) {
      criticalityBreakdown.set(asset.criticality, (criticalityBreakdown.get(asset.criticality) ?? 0) + 1);
    }
    const criticalityOption = {
      tooltip: { trigger: "axis" as const },
      grid: { left: 40, right: 16, top: 16, bottom: 24 },
      xAxis: { type: "category" as const, data: Array.from(criticalityBreakdown.keys()) },
      yAxis: { type: "value" as const },
      series: [
        {
          type: "bar" as const,
          data: Array.from(criticalityBreakdown.values()),
          itemStyle: { color: "#60a5fa", borderRadius: [4, 4, 0, 0] },
        },
      ],
    };

    const widgets: WidgetSpec[] = [
      ...kpis.map((viewModel): WidgetSpec => ({ type: "kpi", span: 1, viewModel })),
    ];

    if (exposureDistributionOption) {
      widgets.push({
        type: "chart",
        span: 2,
        viewModel: {
          id: "exposure-distribution",
          title: "Organizational Exposure Distribution",
          option: exposureDistributionOption,
        },
      });
    } else {
      widgets.push({
        type: "awaiting-integration",
        span: 2,
        viewModel: {
          id: "exposure-distribution",
          title: "Organizational Exposure Distribution",
          reason: "No exposure profile has been computed for this organization yet.",
        },
      });
    }

    widgets.push({
      type: "chart",
      span: 2,
      viewModel: {
        id: "asset-criticality",
        title: "Attack Surface by Business Criticality",
        option: criticalityOption,
        isEmpty: assets.items.length === 0,
        emptyMessage: "No attack surface assets discovered yet.",
      },
    });

    return { id: "executive-overview", widgets };
  },
};
