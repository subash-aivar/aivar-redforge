import type { ReadinessCheck, RuntimeHealth } from "@/lib/types";
import { api } from "@/lib/api";
import * as securityOperations from "@/lib/securityOperations";
import * as ddosApi from "@/lib/ddos";
import * as behaviorApi from "@/lib/behavior";
import * as networkSecurityApi from "@/lib/networkSecurity";
import * as investigationsApi from "@/lib/investigations";
import type { Severity } from "@/design-system/tokens";
import type { DashboardAggregator } from "@/components/dashboard/aggregation/types";
import type { DashboardSpec, WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";
import type { KpiViewModel } from "@/components/dashboard/widgets/KpiCard";
import type { TimelineEntry } from "@/components/dashboard/widgets/TimelineWidget";
import type { AlertEntry } from "@/components/dashboard/widgets/AlertWidget";

/** Settles a promise and returns `fallback` on rejection — matches
 * `socDashboardAggregator`'s own `settle()` contract, duplicated here
 * (not imported) so this aggregator has zero dependency on the Full
 * aggregator module. */
async function settle<T>(promise: Promise<T>, fallback: T): Promise<T> {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

/**
 * Network Defense Edition dashboard aggregator.
 *
 * Every field here traces to a bounded context the Network Defense
 * edition actually mounts (`security-operations`, `ddos`, `behavior`,
 * `network-security`, `investigations`, `runtime`/`health`) — see
 * `backend/src/redforge/api/v1/__init__.py`'s `_Registration.editions`
 * for the authoritative list. Deliberately does NOT call `/targets`,
 * `/findings`, `/risk-incidents`, `/risk-profiles`,
 * `/attack-surface-management/*`, `/vulnerability-platform/*`,
 * `/ai-posture/*`, `/attack-paths`, or
 * `/security-operations/executions` — those bounded contexts are
 * Full-only and absent from a Network Defense deployment's mounted API
 * surface (`test_dashboard_aggregator_edition_composition.test.ts`
 * asserts this aggregator's module never imports any of their client
 * modules). Nothing here is fabricated: a widget with no real data
 * source is omitted, never rendered with a synthetic value.
 */
export const networkDashboardAggregator: DashboardAggregator = {
  id: "network-defense-overview",
  async load({ timeRange }): Promise<DashboardSpec> {
    const period: securityOperations.BoundedPeriod = timeRange === "90d" ? "30d" : timeRange;
    const [
      summary,
      health,
      readiness,
      changes,
      runtimeComponents,
      ddosIncidents,
      behaviorDetections,
      networkInventory,
      investigationPosture,
      investigations,
    ] = await Promise.all([
      settle(securityOperations.getSummary(period), null),
      settle(api.get<RuntimeHealth>("/api/v1/health"), null),
      settle(api.get<ReadinessCheck>("/api/v1/health/ready"), null),
      settle(securityOperations.listChanges({ period, limit: 30 }), []),
      settle(securityOperations.listRuntimeComponents(), []),
      settle(ddosApi.listIncidents({ limit: 20 }), []),
      settle(behaviorApi.listDetections({ limit: 20 }), []),
      settle(networkSecurityApi.getInventory(100, 0), []),
      settle(investigationsApi.getInvestigationPosture(), null),
      settle(investigationsApi.listInvestigations({ limit: 15 }), []),
    ]);

    const activeDdosIncidents = ddosIncidents.filter((i) => i.status !== "resolved").length;
    const openDetections = behaviorDetections.filter((d) => d.status !== "closed").length;

    // ── KPI wall — every value traces to a Network Defense-valid source ──
    const kpis: KpiViewModel[] = [
      {
        id: "ddos-incidents",
        label: "DDoS Incidents",
        value: activeDdosIncidents,
        sublabel: "Currently active",
        severity: activeDdosIncidents > 0 ? "high" : undefined,
      },
      {
        id: "behavior-detections",
        label: "Behavior Detections",
        value: openDetections,
        sublabel: "Open NDR detections",
      },
      {
        id: "network-assets",
        label: "Network Assets Monitored",
        value: networkInventory.length,
        sublabel: "Network security inventory",
      },
      {
        id: "conditions",
        label: "Critical/High Conditions",
        value: summary?.critical_high_conditions ?? 0,
        sublabel: "Active security conditions",
        severity: (summary?.critical_high_conditions ?? 0) > 0 ? "high" : undefined,
      },
      {
        id: "correlations",
        label: "Active Correlations",
        value: summary?.active_correlations ?? 0,
        sublabel: "Cross-domain correlation engine",
      },
      {
        id: "investigations-open",
        label: "Open Investigations",
        value: investigationPosture?.total_active ?? 0,
        sublabel: "Cross-domain cases",
      },
      {
        id: "investigations-critical",
        label: "Critical Investigations",
        value: investigationPosture?.critical_cases ?? 0,
        sublabel: "Require immediate action",
        severity: (investigationPosture?.critical_cases ?? 0) > 0 ? "critical" : undefined,
      },
      {
        id: "runtime-unhealthy",
        label: "Unhealthy Components",
        value: summary?.runtime_unhealthy_components ?? 0,
        sublabel: "Platform runtime",
        severity: (summary?.runtime_unhealthy_components ?? 0) > 0 ? "high" : undefined,
      },
    ];

    // ── Platform/runtime health as alerts — identical shape to the Full
    // dashboard's own construction (this data is shared/ND-valid) ──────
    const healthAlerts: AlertEntry[] = [
      {
        id: "app-status",
        title: `Application: ${health?.status ?? "unknown"}`,
        severity: health?.status === "healthy" ? "informational" : "high",
        timestamp: health?.timestamp ?? new Date().toISOString(),
      },
      {
        id: "db-status",
        title: `Database: ${readiness?.checks?.database ?? "unknown"}`,
        severity: readiness?.checks?.database === "ready" ? "informational" : "high",
        timestamp: new Date().toISOString(),
      },
      ...runtimeComponents.map((c) => ({
        id: c.component_id,
        title: `${c.component_id}: ${c.status}`,
        detail: c.message,
        severity: c.status === "healthy" ? ("informational" as Severity) : ("high" as Severity),
        timestamp: c.checked_at,
      })),
    ];

    const changeTimeline: TimelineEntry[] = changes.map((c) => ({
      id: c.event_id,
      timestamp: c.occurred_at,
      title: c.title,
      summary: c.summary,
      severity: importanceToSeverity(c.importance),
      sourceLabel: c.source_domain,
    }));

    const ddosTimeline: TimelineEntry[] = [...ddosIncidents]
      .sort((a, b) => b.first_detected_at.localeCompare(a.first_detected_at))
      .slice(0, 10)
      .map((incident) => ({
        id: incident.id,
        timestamp: incident.first_detected_at,
        title: `${incident.resource_name} — ${incident.classification}`,
        summary: `${incident.status} · ${incident.severity}`,
        severity: (incident.severity?.toLowerCase() as Severity) ?? "informational",
        sourceLabel: "ddos",
      }));

    const behaviorTimeline: TimelineEntry[] = [...behaviorDetections]
      .sort((a, b) => b.detected_at.localeCompare(a.detected_at))
      .slice(0, 10)
      .map((detection) => ({
        id: detection.id,
        timestamp: detection.detected_at,
        title: detection.detection_type,
        summary: `${detection.status} · ${detection.observation_count} observation(s)`,
        severity: (detection.severity?.toLowerCase() as Severity) ?? "informational",
        sourceLabel: "behavior",
      }));

    const investigationTimeline: TimelineEntry[] = [...investigations]
      .sort((a, b) => b.opened_at.localeCompare(a.opened_at))
      .slice(0, 10)
      .map((investigation) => ({
        id: investigation.id,
        timestamp: investigation.opened_at,
        title: investigation.title,
        summary: `${investigation.status} · ${investigation.source_domains.join(", ")}`,
        severity: (investigation.severity?.toLowerCase() as Severity) ?? "informational",
        sourceLabel: "investigation",
      }));

    const widgets: WidgetSpec[] = [
      ...kpis.map((viewModel): WidgetSpec => ({ type: "kpi", span: 1, viewModel })),
      {
        type: "live-feed",
        span: 2,
        viewModel: { id: "live-feed", title: "Live Security Operations Feed" },
      },
      {
        type: "alerts",
        span: 2,
        viewModel: {
          id: "platform-health",
          title: "Platform & Runtime Health",
          alerts: healthAlerts,
          emptyMessage: "No platform health data available.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "soc-change-feed",
          title: "Network Incident & Change Stream",
          entries: changeTimeline,
          emptyMessage: "No operational changes in the last 24h.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "ddos-incident-timeline",
          title: "Recent DDoS Incidents",
          entries: ddosTimeline,
          emptyMessage: "No DDoS incidents recorded.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "behavior-detection-timeline",
          title: "Recent Behavior Detections",
          entries: behaviorTimeline,
          emptyMessage: "No behavior detections recorded.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "investigation-timeline",
          title: "Recent Investigations",
          entries: investigationTimeline,
          emptyMessage: "No cross-domain investigations recorded.",
        },
      },
    ];

    return { id: "network-defense-overview", widgets };
  },
};

function importanceToSeverity(importance: securityOperations.OperationalImportance): Severity {
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
