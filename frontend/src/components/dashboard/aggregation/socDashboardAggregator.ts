import { api, getOrganizationId } from "@/lib/api";
import type { Finding, ReadinessCheck, RiskIncident, RiskIncidentList, RuntimeHealth, Target } from "@/lib/types";
import * as securityOperations from "@/lib/securityOperations";
import * as riskEngine from "@/lib/riskEngine";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import * as vulnerabilityApi from "@/lib/vulnerability";
import * as ddosApi from "@/lib/ddos";
import * as behaviorApi from "@/lib/behavior";
import * as aiPostureApi from "@/lib/ai-posture";
import * as attackPathsApi from "@/lib/attackPathsApi";
import type { Severity } from "@/design-system/tokens";
import type { DashboardAggregator } from "@/components/dashboard/aggregation/types";
import type { DashboardSpec, WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";
import type { KpiViewModel } from "@/components/dashboard/widgets/KpiCard";
import type { TimelineEntry } from "@/components/dashboard/widgets/TimelineWidget";
import type { AlertEntry } from "@/components/dashboard/widgets/AlertWidget";
import type { GraphModel } from "@/components/dashboard/graph/graphTypes";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

/** Settles a promise and returns `fallback` on rejection — the same
 * degrade-gracefully-never-crash contract `dashboard/page.tsx`
 * already established with `Promise.allSettled`, generalized into a
 * helper so every source in this much larger fan-out reads the same
 * way. A bounded context that 403s, isn't deployed, or is simply slow
 * never takes the whole dashboard down with it — it just contributes
 * nothing to that one widget. */
async function settle<T>(promise: Promise<T>, fallback: T): Promise<T> {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

/**
 * Security Operations SOC dashboard aggregator.
 *
 * Every field below traces to a real, already-implemented backend
 * endpoint — see the inline citations. Nothing here is a random
 * number or a synthetic event. Where a named visualization from the
 * platform-realization brief has no real backing data yet (MITRE
 * ATT&CK observed-technique coverage, threat-actor relationship
 * graphs, a cross-org risk heatmap, a compliance score radar, a geo
 * attack map, AI Red Team activity), it is deliberately NOT rendered
 * here — the dashboard page renders an honest "Awaiting platform
 * integration" panel for each instead of a fabricated chart.
 */
export const socDashboardAggregator: DashboardAggregator = {
  id: "soc-overview",
  async load({ timeRange }): Promise<DashboardSpec> {
    // The security-operations backbone's own BoundedPeriod is
    // narrower than the dashboard's TimeRangeSelector ("90d" has no
    // backend equivalent yet) — clamped to the widest period the
    // backend genuinely supports rather than silently ignored.
    const period: securityOperations.BoundedPeriod = timeRange === "90d" ? "30d" : timeRange;
    const [
      summary,
      health,
      readiness,
      targets,
      findings,
      riskIncidents,
      executions,
      changes,
      runtimeComponents,
      riskProfiles,
      assets,
      vulnerabilities,
      ddosIncidents,
      behaviorDetections,
      aiInventory,
      attackPaths,
    ] = await Promise.all([
      settle(securityOperations.getSummary(period), null),
      settle(api.get<RuntimeHealth>("/api/v1/health"), null),
      settle(api.get<ReadinessCheck>("/api/v1/health/ready"), null),
      settle(api.get<Target[]>("/api/v1/targets"), [] as Target[]),
      settle(api.get<Finding[]>("/api/v1/findings"), [] as Finding[]),
      settle(
        api.get<RiskIncidentList>("/api/v1/risk-incidents").then((r) => r.items),
        [] as RiskIncident[]
      ),
      settle(securityOperations.listExecutions({ limit: 20 }), []),
      settle(securityOperations.listChanges({ period, limit: 30 }), []),
      settle(securityOperations.listRuntimeComponents(), []),
      settle(riskEngine.listRiskProfiles({ limit: 100 }), { items: [], count: 0 }),
      settle(attackSurfaceManagement.listAssets({ limit: 100 }), { items: [], count: 0 }),
      // `listVulnerabilities`/`getVulnerability` no longer exist as a
      // list route in the canonical `vulnerability` bounded context
      // (Slice 3 audit — see `lib/vulnerability.ts`'s header comment);
      // the real pre-aggregated `instance-summary` read-model is both
      // the correct replacement and cheaper (one query, not N).
      settle(vulnerabilityApi.getInstanceSummary(), {
        tenant_id: "",
        by_severity: {},
        by_state: {},
        total_open: 0,
        total_resolved: 0,
        last_updated_at: "",
      }),
      settle(ddosApi.listIncidents({ limit: 20 }), []),
      settle(behaviorApi.listDetections({ limit: 20 }), []),
      settle(aiPostureApi.getInventoryDashboard(), null),
      // Requires PlatformPermission — a regular org user will 403 here,
      // which `settle()` degrades to an empty list rather than a crash.
      // The organization_id guard avoids even attempting the call when
      // no org is selected yet.
      getOrganizationId()
        ? settle(attackPathsApi.listAttackPaths({ organization_id: getOrganizationId()!, limit: 5 }), [])
        : Promise.resolve([]),
    ]);

    const findingCount = (severity: Severity) =>
      findings.filter((f) => f.severity?.toLowerCase() === severity).length;
    const vulnCount = (severity: Severity) => vulnerabilities.by_severity?.[severity] ?? 0;
    const activeDdosIncidents = ddosIncidents.filter((i) => i.status !== "resolved").length;
    const openDetections = behaviorDetections.filter((d) => d.status !== "closed").length;

    // ── KPI wall ──────────────────────────────────────────────────────
    const kpis: KpiViewModel[] = [
      { id: "targets", label: "AI Targets", value: targets.length, sublabel: "Under validation" },
      {
        id: "assets",
        label: "Attack Surface Assets",
        value: assets.count,
        sublabel: "Discovered assets",
      },
      {
        id: "critical-findings",
        label: "Critical Findings",
        value: findingCount("critical"),
        sublabel: "Require immediate action",
        severity: findingCount("critical") > 0 ? "critical" : undefined,
      },
      {
        id: "critical-vulns",
        label: "Critical Vulnerabilities",
        value: vulnCount("critical"),
        sublabel: `${vulnerabilities.total_open ?? 0} open total`,
        severity: vulnCount("critical") > 0 ? "critical" : undefined,
      },
      {
        id: "risk-profiles",
        label: "Risk Profiles",
        value: riskProfiles.count,
        sublabel: "Enterprise Risk Engine",
      },
      {
        id: "conditions",
        label: "Critical/High Conditions",
        value: summary?.critical_high_conditions ?? 0,
        sublabel: "Active security conditions",
        severity: (summary?.critical_high_conditions ?? 0) > 0 ? "high" : undefined,
      },
      {
        id: "validations-running",
        label: "Validations Running",
        value: summary?.validations_running ?? 0,
        sublabel: "Continuous validation",
      },
      {
        id: "validations-blocked",
        label: "Validations Blocked",
        value: summary?.validations_blocked_in_period ?? 0,
        sublabel: "Last 24h",
        severity: (summary?.validations_blocked_in_period ?? 0) > 0 ? "medium" : undefined,
      },
      {
        id: "correlations",
        label: "Active Correlations",
        value: summary?.active_correlations ?? 0,
        sublabel: "Cross-domain correlation engine",
      },
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
        id: "runtime-unhealthy",
        label: "Unhealthy Components",
        value: summary?.runtime_unhealthy_components ?? 0,
        sublabel: "Platform runtime",
        severity: (summary?.runtime_unhealthy_components ?? 0) > 0 ? "high" : undefined,
      },
    ];

    // ── Findings + vulnerability severity charts (real ECharts options) ──
    const findingsBySeverityOption = {
      tooltip: { trigger: "item" as const },
      legend: { top: "bottom", textStyle: { color: "#9ca3af", fontSize: 10 } },
      series: [
        {
          type: "pie" as const,
          radius: ["45%", "70%"],
          itemStyle: { borderColor: "#111827", borderWidth: 2 },
          label: { color: "#d1d5db" },
          data: SEVERITIES.map((s) => ({ name: s, value: findingCount(s) })).filter((d) => d.value > 0),
        },
      ],
    };

    const vulnBySeverityOption = {
      tooltip: { trigger: "axis" as const },
      grid: { left: 40, right: 16, top: 16, bottom: 24 },
      xAxis: { type: "category" as const, data: SEVERITIES },
      yAxis: { type: "value" as const },
      series: [
        {
          type: "bar" as const,
          data: SEVERITIES.map((s) => vulnCount(s)),
          itemStyle: { color: "#f87171", borderRadius: [4, 4, 0, 0] },
        },
      ],
    };

    // ── Asset exposure treemap (real ECharts treemap over real assets) ──
    const exposureGroups = new Map<string, number>();
    for (const asset of assets.items) {
      const key = asset.exposure_state || "unknown";
      exposureGroups.set(key, (exposureGroups.get(key) ?? 0) + 1);
    }
    const exposureTreemapOption = {
      tooltip: { formatter: "{b}: {c} assets" },
      series: [
        {
          type: "treemap" as const,
          data: Array.from(exposureGroups.entries()).map(([name, value]) => ({ name, value })),
          label: { color: "#e5e7eb" },
          breadcrumb: { show: false },
          itemStyle: { borderColor: "#111827" },
        },
      ],
    };

    // ── Execution + change-feed timelines (real M15 data) ──────────────
    const executionTimeline: TimelineEntry[] = executions.map((e) => ({
      id: e.id,
      timestamp: e.started_at ?? e.created_at,
      title: `${e.trigger} · ${e.profile}`,
      summary: e.latest_event_title ?? e.phase,
      sourceLabel: e.state,
    }));

    const changeTimeline: TimelineEntry[] = changes.map((c) => ({
      id: c.event_id,
      timestamp: c.occurred_at,
      title: c.title,
      summary: c.summary,
      severity: importanceToSeverity(c.importance),
      sourceLabel: c.source_domain,
    }));

    // ── Runtime/module health as alerts ─────────────────────────────────
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

    // ── Risk incident + DDoS + behavior tables ──────────────────────────
    const riskIncidentTimeline: TimelineEntry[] = [...riskIncidents]
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, 15)
      .map((incident) => ({
        id: incident.id,
        timestamp: incident.created_at,
        title: incident.title,
        summary: `Score ${incident.score} · ${incident.status}`,
        severity: (incident.severity?.toLowerCase() as Severity) ?? "informational",
        sourceLabel: "risk",
      }));

    // ── Attack path graph (real AttackPath.steps, platform-permission
    // gated — empty when unavailable rather than fabricated) ──────────
    const topPath = attackPaths[0];
    const attackPathGraph: GraphModel | null =
      topPath?.steps && topPath.steps.length > 0
        ? {
            nodes: topPath.steps.map((step) => ({
              id: String(step.sequence),
              label: step.canonical_key,
              kind: step.step_type,
              severity: confidenceToSeverity(step.confidence),
            })),
            edges: topPath.steps.slice(1).map((step) => ({
              id: `${step.sequence - 1}-${step.sequence}`,
              source: String(step.sequence - 1),
              target: String(step.sequence),
              label: step.relationship_type ?? undefined,
            })),
          }
        : null;

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
        type: "chart",
        span: 1,
        viewModel: {
          id: "findings-by-severity",
          title: "Findings by Severity",
          option: findingsBySeverityOption,
          isEmpty: findings.length === 0,
          emptyMessage: "No findings yet. Run a red-team campaign to generate security findings.",
        },
      },
      {
        type: "chart",
        span: 1,
        viewModel: {
          id: "vuln-by-severity",
          title: "Critical Vulnerability Matrix",
          option: vulnBySeverityOption,
          isEmpty: !!vulnerabilities.empty || (vulnerabilities.total_open === 0 && vulnerabilities.total_resolved === 0),
          emptyMessage: "No vulnerabilities tracked yet.",
        },
      },
      {
        type: "chart",
        span: 2,
        viewModel: {
          id: "asset-exposure-treemap",
          title: "Attack Surface Exposure Treemap",
          option: exposureTreemapOption,
          isEmpty: assets.items.length === 0,
          emptyMessage: "No attack surface assets discovered yet.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "validation-execution-timeline",
          title: "Validation Execution Timeline",
          entries: executionTimeline,
          emptyMessage: "No validation executions recorded.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "soc-change-feed",
          title: "SOC Incident & Change Stream",
          entries: changeTimeline,
          emptyMessage: "No operational changes in the last 24h.",
        },
      },
      {
        type: "timeline",
        span: 2,
        viewModel: {
          id: "risk-incident-timeline",
          title: "Recent Risk Incidents",
          entries: riskIncidentTimeline,
          emptyMessage: "No risk incidents recorded.",
        },
      },
      // Named visualizations with no real backing data source yet —
      // rendered honestly rather than fabricated. Each reason cites the
      // specific missing capability, not a generic placeholder.
      {
        type: "awaiting-integration",
        span: 2,
        viewModel: {
          id: "mitre-coverage",
          title: "MITRE ATT&CK Coverage",
          reason:
            "Requires a cross-organization observed-technique aggregate. Reference-data tactics/techniques exist (redforge.domain.threat_intel), but no backend endpoint yet computes which techniques this tenant has actually observed vs. the full taxonomy.",
        },
      },
      {
        type: "awaiting-integration",
        span: 2,
        viewModel: {
          id: "threat-actor-relationships",
          title: "Threat Actor Relationships",
          reason:
            "The ThreatActor domain (threat_actor_intel, M51A) is domain-layer only — no application, infrastructure, or API exists yet to query threat-actor-to-technique/indicator relationships.",
        },
      },
      {
        type: "awaiting-integration",
        span: 2,
        viewModel: {
          id: "global-attack-map",
          title: "Global Attack Map",
          reason:
            "No backend source currently returns geo-located attack/indicator coordinates for this tenant. MapWidget is ready (MapLibre) once such an endpoint exists.",
        },
      },
      {
        type: "awaiting-integration",
        span: 1,
        viewModel: {
          id: "org-risk-heatmap",
          title: "Organization Risk Heatmap",
          reason:
            "Requires a cross-organization risk aggregate; single-tenant Risk Engine data exists, but no platform-level multi-org rollup endpoint exists yet.",
        },
      },
      {
        type: "awaiting-integration",
        span: 1,
        viewModel: {
          id: "compliance-radar",
          title: "Compliance Posture Radar",
          reason:
            "Compliance profiles/frameworks exist, but no endpoint returns a per-framework numeric score suitable for a radar chart yet.",
        },
      },
      {
        type: "awaiting-integration",
        span: 2,
        viewModel: {
          id: "ai-red-team-timeline",
          title: "AI Red Team Activity Timeline",
          reason:
            "ai_security has a domain and application layer but no infrastructure or API layer yet (confirmed empty stub packages) — there is no execution data to surface.",
        },
      },
    ];

    if (attackPathGraph) {
      widgets.push({
        type: "graph",
        span: 2,
        viewModel: {
          id: "attack-path-graph",
          title: `Attack Path — ${topPath.attributed_actors.join(", ") || "unattributed"}`,
          model: attackPathGraph,
          emptyMessage: "No computed attack paths for this organization yet.",
        },
      });
    }

    if (aiInventory) {
      widgets.push({
        type: "kpi",
        span: 1,
        viewModel: {
          id: "ai-assets",
          label: "AI Assets Inventoried",
          value: aiInventory.assets.length,
          sublabel: aiInventory.coverage_scope,
        },
      });
    }

    return { id: "soc-overview", widgets };
  },
};

/** `AttackStep.confidence` ("high"/"medium"/"low"/"very_low", per
 * `attackPathsApi.stepConfidenceColor`'s own vocabulary) -> `Severity`,
 * so a low-confidence step reads visually as lower-priority on the
 * graph, consistent with everywhere else severity color is used. */
function confidenceToSeverity(confidence: string): Severity {
  switch (confidence.toLowerCase()) {
    case "high":
      return "low"; // high path-confidence = well-understood, not itself an alert
    case "medium":
      return "medium";
    case "low":
      return "high";
    case "very_low":
      return "critical";
    default:
      return "informational";
  }
}

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
