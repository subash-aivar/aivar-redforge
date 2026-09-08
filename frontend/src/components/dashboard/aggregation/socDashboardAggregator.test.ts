import { describe, it, expect, vi, beforeEach } from "vitest";
import { api, getOrganizationId } from "@/lib/api";
import * as securityOperations from "@/lib/securityOperations";
import * as riskEngine from "@/lib/riskEngine";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import * as vulnerabilityApi from "@/lib/vulnerability";
import * as ddosApi from "@/lib/ddos";
import * as behaviorApi from "@/lib/behavior";
import * as aiPostureApi from "@/lib/ai-posture";
import * as attackPathsApi from "@/lib/attackPathsApi";
import { socDashboardAggregator } from "@/components/dashboard/aggregation/socDashboardAggregator";
import type { WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, get: vi.fn() }, getOrganizationId: vi.fn() };
});
vi.mock("@/lib/securityOperations");
vi.mock("@/lib/riskEngine");
vi.mock("@/lib/attackSurfaceManagement");
vi.mock("@/lib/vulnerability");
vi.mock("@/lib/ddos");
vi.mock("@/lib/behavior");
vi.mock("@/lib/ai-posture");
vi.mock("@/lib/attackPathsApi");

function widgetsOfType(widgets: WidgetSpec[], type: WidgetSpec["type"]): WidgetSpec[] {
  return widgets.filter((w) => w.type === type);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getOrganizationId).mockReturnValue(null);
  vi.mocked(api.get).mockRejectedValue(new Error("not mocked"));
  vi.mocked(securityOperations.getSummary).mockRejectedValue(new Error("not mocked"));
  vi.mocked(securityOperations.listExecutions).mockRejectedValue(new Error("not mocked"));
  vi.mocked(securityOperations.listChanges).mockRejectedValue(new Error("not mocked"));
  vi.mocked(securityOperations.listRuntimeComponents).mockRejectedValue(new Error("not mocked"));
  vi.mocked(riskEngine.listRiskProfiles).mockRejectedValue(new Error("not mocked"));
  vi.mocked(attackSurfaceManagement.listAssets).mockRejectedValue(new Error("not mocked"));
  vi.mocked(vulnerabilityApi.getInstanceSummary).mockRejectedValue(new Error("not mocked"));
  vi.mocked(ddosApi.listIncidents).mockRejectedValue(new Error("not mocked"));
  vi.mocked(behaviorApi.listDetections).mockRejectedValue(new Error("not mocked"));
  vi.mocked(aiPostureApi.getInventoryDashboard).mockRejectedValue(new Error("not mocked"));
});

describe("socDashboardAggregator", () => {
  it("degrades gracefully when every source is unavailable — never throws", async () => {
    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    expect(spec.id).toBe("soc-overview");
    expect(spec.widgets.length).toBeGreaterThan(0);
  });

  it("shapes KPI counts from real findings/vulnerabilities/summary data, never a random number", async () => {
    vi.mocked(api.get).mockImplementation((path: string) => {
      if (path === "/api/v1/findings") {
        return Promise.resolve([{ id: "f1", severity: "critical" }, { id: "f2", severity: "low" }]);
      }
      if (path === "/api/v1/targets") return Promise.resolve([{ id: "t1" }]);
      if (path === "/api/v1/risk-incidents") return Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 });
      return Promise.reject(new Error("not mocked"));
    });
    vi.mocked(vulnerabilityApi.getInstanceSummary).mockResolvedValue({
      tenant_id: "t1",
      by_severity: { critical: 1 },
      by_state: {},
      total_open: 1,
      total_resolved: 0,
      last_updated_at: new Date(0).toISOString(),
    });

    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    const kpis = widgetsOfType(spec.widgets, "kpi");
    const critical = kpis.find((w) => w.type === "kpi" && w.viewModel.id === "critical-findings");
    const criticalVulns = kpis.find((w) => w.type === "kpi" && w.viewModel.id === "critical-vulns");
    expect(critical && critical.type === "kpi" ? critical.viewModel.value : null).toBe(1);
    expect(criticalVulns && criticalVulns.type === "kpi" ? criticalVulns.viewModel.value : null).toBe(1);
  });

  it("never throws when the vulnerability read-model returns its real empty-tenant shape ({tenant_id, empty:true}, no by_severity)", async () => {
    // Regression test for a real bug found in browser QA: a brand-new
    // tenant's `/vulnerability-platform/read-models/instance-summary`
    // resolves (200 OK, not rejected) with only `{tenant_id, empty:true}`
    // — `by_severity`/`total_open`/`total_resolved` are absent, not
    // empty objects/zero. `vulnCount()` crashed on this exact shape.
    vi.mocked(vulnerabilityApi.getInstanceSummary).mockResolvedValue({
      tenant_id: "t1",
      empty: true,
    } as never);

    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    const kpis = widgetsOfType(spec.widgets, "kpi");
    const criticalVulns = kpis.find((w) => w.type === "kpi" && w.viewModel.id === "critical-vulns");
    expect(criticalVulns && criticalVulns.type === "kpi" ? criticalVulns.viewModel.value : null).toBe(0);

    const chart = widgetsOfType(spec.widgets, "chart").find(
      (w) => w.type === "chart" && w.viewModel.id === "vuln-by-severity"
    );
    expect(chart && chart.type === "chart" ? chart.viewModel.isEmpty : null).toBe(true);
  });

  it("unwraps the real risk-incidents paginated envelope ({items,total,limit,offset}) instead of crashing on a bare-array assumption", async () => {
    // Regression test: `/api/v1/risk-incidents` returns a paginated
    // envelope, not a bare array — `[...riskIncidents]` crashed with
    // "riskIncidents is not iterable" against the real endpoint.
    vi.mocked(api.get).mockImplementation((path: string) => {
      if (path === "/api/v1/risk-incidents") {
        return Promise.resolve({
          items: [
            {
              id: "inc-1",
              title: "Test incident",
              severity: "high",
              score: 7.2,
              status: "open",
              affected_targets: [],
              finding_ids: [],
              created_at: new Date(0).toISOString(),
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return Promise.reject(new Error("not mocked"));
    });

    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    const timelines = widgetsOfType(spec.widgets, "timeline");
    const riskTimeline = timelines.find(
      (w) => w.type === "timeline" && w.viewModel.id === "risk-incident-timeline"
    );
    expect(riskTimeline && riskTimeline.type === "timeline" ? riskTimeline.viewModel.entries : []).toHaveLength(1);
  });

  it("always includes the honest awaiting-integration panels for capabilities with no real data source", async () => {
    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    const ids = widgetsOfType(spec.widgets, "awaiting-integration").map((w) =>
      w.type === "awaiting-integration" ? w.viewModel.id : null
    );
    expect(ids).toEqual(
      expect.arrayContaining([
        "mitre-coverage",
        "threat-actor-relationships",
        "global-attack-map",
        "org-risk-heatmap",
        "compliance-radar",
        "ai-red-team-timeline",
      ])
    );
  });

  it("only renders the attack-path graph when a real path with steps exists", async () => {
    vi.mocked(getOrganizationId).mockReturnValue("org-1");
    vi.mocked(attackPathsApi.listAttackPaths).mockResolvedValue([]);

    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    expect(widgetsOfType(spec.widgets, "graph")).toHaveLength(0);
  });

  it("builds a real graph model from AttackPath.steps when present", async () => {
    vi.mocked(getOrganizationId).mockReturnValue("org-1");
    vi.mocked(attackPathsApi.listAttackPaths).mockResolvedValue([
      {
        id: "p1",
        organization_id: "org-1",
        root_entity_id: "e1",
        root_canonical_key: "k1",
        terminal_entity_id: null,
        path_confidence: "high",
        technique_coverage: [],
        attributed_actors: ["APT29"],
        step_count: 2,
        evidence_count: 1,
        max_exposure_score: 5,
        status: "active",
        alternate_path_count: 0,
        steps: [
          {
            sequence: 0,
            entity_id: "e1",
            canonical_key: "k1",
            step_type: "asset",
            confidence: "high",
            technique_id: null,
            evidence_refs: [],
            relationship_type: null,
            kill_chain_phase: null,
            inferred_from_step: null,
            exposure_score: 5,
          },
          {
            sequence: 1,
            entity_id: "e2",
            canonical_key: "k2",
            step_type: "asset",
            confidence: "low",
            technique_id: "T1566",
            evidence_refs: [],
            relationship_type: "exploits",
            kill_chain_phase: null,
            inferred_from_step: 0,
            exposure_score: 8,
          },
        ],
      },
    ]);

    const spec = await socDashboardAggregator.load({ timeRange: "24h", filters: {} });
    const graphs = widgetsOfType(spec.widgets, "graph");
    expect(graphs).toHaveLength(1);
    const graph = graphs[0];
    if (graph.type !== "graph") throw new Error("expected graph widget");
    expect(graph.viewModel.model.nodes).toHaveLength(2);
    expect(graph.viewModel.model.edges).toHaveLength(1);
    expect(graph.viewModel.title).toContain("APT29");
  });

  it("clamps a 90d time range to the backend's widest supported BoundedPeriod (30d)", async () => {
    await socDashboardAggregator.load({ timeRange: "90d", filters: {} });
    expect(securityOperations.getSummary).toHaveBeenCalledWith("30d");
  });
});
