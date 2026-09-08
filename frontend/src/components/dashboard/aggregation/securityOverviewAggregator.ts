import { api } from "@/lib/api";
import type { Finding, ReadinessCheck, RiskIncidentList, RuntimeHealth, Target } from "@/lib/types";
import type { Severity } from "@/design-system/tokens";
import type { DashboardAggregator } from "@/components/dashboard/aggregation/types";
import type { DashboardSpec, WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";
import type { KpiViewModel } from "@/components/dashboard/widgets/KpiCard";
import type { TimelineEntry } from "@/components/dashboard/widgets/TimelineWidget";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

/**
 * Security Overview aggregator — the concrete, real implementation of
 * `DashboardAggregator` behind the platform's general security
 * dashboard.
 *
 * Reads exactly the same bounded-context endpoints
 * `dashboard/page.tsx` already calls (`/api/v1/health`,
 * `/api/v1/health/ready`, `/api/v1/targets`, `/api/v1/findings`,
 * `/api/v1/risk-incidents`) — no new backend surface, no fabricated
 * data — and reshapes them into a `DashboardSpec`. This is the
 * reference implementation every other persona aggregator should
 * follow the shape of.
 */
export const securityOverviewAggregator: DashboardAggregator = {
  id: "security-overview",
  async load(): Promise<DashboardSpec> {
    const [health, readiness, targets, findings, riskIncidents] = await Promise.allSettled([
      api.get<RuntimeHealth>("/api/v1/health"),
      api.get<ReadinessCheck>("/api/v1/health/ready"),
      api.get<Target[]>("/api/v1/targets"),
      api.get<Finding[]>("/api/v1/findings"),
      api.get<RiskIncidentList>("/api/v1/risk-incidents"),
    ]);

    const targetList = targets.status === "fulfilled" && Array.isArray(targets.value) ? targets.value : [];
    const findingList = findings.status === "fulfilled" && Array.isArray(findings.value) ? findings.value : [];
    const incidentList =
      riskIncidents.status === "fulfilled" && Array.isArray(riskIncidents.value?.items)
        ? riskIncidents.value.items
        : [];
    const healthValue = health.status === "fulfilled" ? health.value : null;
    const readinessValue = readiness.status === "fulfilled" ? readiness.value : null;

    const countBySeverity = (severity: Severity) =>
      findingList.filter((f) => f.severity?.toLowerCase() === severity).length;

    const kpis: KpiViewModel[] = [
      { id: "targets", label: "AI Targets", value: targetList.length, sublabel: "Under validation" },
      {
        id: "critical-findings",
        label: "Critical Findings",
        value: countBySeverity("critical"),
        sublabel: "Require immediate action",
        severity: "critical",
      },
      {
        id: "high-findings",
        label: "High Findings",
        value: countBySeverity("high"),
        sublabel: "Security concerns",
        severity: "high",
      },
      {
        id: "risk-incidents",
        label: "Risk Incidents",
        value: incidentList.length,
        sublabel: "Active incidents",
        severity: incidentList.length > 0 ? "medium" : undefined,
      },
    ];

    const findingsBySeverityOption = {
      tooltip: { trigger: "item" as const },
      series: [
        {
          type: "pie" as const,
          radius: ["45%", "70%"],
          itemStyle: { borderColor: "#111827", borderWidth: 2 },
          label: { color: "#d1d5db" },
          data: SEVERITIES.map((s) => ({ name: s, value: countBySeverity(s) })).filter(
            (d) => d.value > 0
          ),
        },
      ],
    };

    const incidentTimeline: TimelineEntry[] = [...incidentList]
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, 20)
      .map((incident) => ({
        id: incident.id,
        timestamp: incident.created_at,
        title: incident.title,
        summary: `Score ${incident.score} · ${incident.status}`,
        severity: (incident.severity?.toLowerCase() as Severity) ?? "informational",
        sourceLabel: "risk",
      }));

    const widgets: WidgetSpec[] = [
      ...kpis.map((viewModel): WidgetSpec => ({ type: "kpi", span: 1, viewModel })),
      {
        type: "chart",
        span: 2,
        viewModel: {
          id: "findings-by-severity",
          title: "Findings by Severity",
          option: findingsBySeverityOption,
          isEmpty: findingList.length === 0,
          emptyMessage: "No findings yet. Run a red-team campaign to generate security findings.",
        },
      },
      {
        type: "live-feed",
        span: 2,
        viewModel: { id: "live-feed" },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "risk-incident-timeline",
          title: "Recent Risk Incidents",
          entries: incidentTimeline,
          emptyMessage: "No risk incidents recorded.",
        },
      },
      {
        type: "alerts",
        span: 2,
        viewModel: {
          id: "platform-status",
          title: "Platform Status",
          alerts: [
            {
              id: "app-status",
              title: `Application: ${healthValue?.status ?? "unknown"}`,
              severity: healthValue?.status === "healthy" ? "informational" : "high",
              timestamp: healthValue?.timestamp ?? new Date().toISOString(),
            },
            {
              id: "db-status",
              title: `Database: ${readinessValue?.checks?.database ?? "unknown"}`,
              severity: readinessValue?.checks?.database === "ready" ? "informational" : "high",
              timestamp: new Date().toISOString(),
            },
          ],
          emptyMessage: "No platform status available.",
        },
      },
    ];

    return { id: "security-overview", widgets };
  },
};
