import { describe, it, expect, vi, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import * as securityOperations from "@/lib/securityOperations";
import * as ddosApi from "@/lib/ddos";
import * as behaviorApi from "@/lib/behavior";
import * as networkSecurityApi from "@/lib/networkSecurity";
import * as investigationsApi from "@/lib/investigations";
import { api } from "@/lib/api";
import { networkDashboardAggregator } from "@/components/dashboard/aggregation/networkDashboardAggregator";

afterEach(() => {
  vi.restoreAllMocks();
});

// Excluded Full-only client modules — the exact set the live-browser
// audit (Phase 0.2.1 Workstream 2.1) found `/dashboard` calling under
// network_defense. This is a static source-text guard (not a runtime
// mock count) so it fails the instant anyone re-adds one of these
// imports to this file, without depending on every call actually being
// exercised in a given test run.
const EXCLUDED_MODULE_IMPORTS = [
  '"@/lib/riskEngine"',
  '"@/lib/attackSurfaceManagement"',
  '"@/lib/vulnerability"',
  '"@/lib/ai-posture"',
  '"@/lib/attackPathsApi"',
];
const EXCLUDED_ENDPOINT_LITERALS = [
  "/api/v1/targets",
  "/api/v1/findings",
  "/api/v1/risk-incidents",
  "listExecutions",
];

describe("networkDashboardAggregator — edition composition", () => {
  it("never imports a Full-only bounded-context client module", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "networkDashboardAggregator.ts"),
      "utf-8"
    );
    for (const excludedImport of EXCLUDED_MODULE_IMPORTS) {
      expect(source).not.toContain(excludedImport);
    }
    for (const excludedLiteral of EXCLUDED_ENDPOINT_LITERALS) {
      expect(source).not.toContain(excludedLiteral);
    }
  });

  it("never calls a Full-only client function even when spied on directly", async () => {
    const targetsSpy = vi.spyOn(api, "get");
    vi.spyOn(securityOperations, "getSummary").mockResolvedValue(null as never);
    vi.spyOn(securityOperations, "listChanges").mockResolvedValue([]);
    vi.spyOn(securityOperations, "listRuntimeComponents").mockResolvedValue([]);
    vi.spyOn(ddosApi, "listIncidents").mockResolvedValue([]);
    vi.spyOn(behaviorApi, "listDetections").mockResolvedValue([]);
    vi.spyOn(networkSecurityApi, "getInventory").mockResolvedValue([]);
    vi.spyOn(investigationsApi, "getInvestigationPosture").mockResolvedValue(null as never);
    vi.spyOn(investigationsApi, "listInvestigations").mockResolvedValue([]);

    await networkDashboardAggregator.load({ timeRange: "24h", filters: {} });

    const calledPaths = targetsSpy.mock.calls.map((c) => String(c[0]));
    for (const excludedPath of ["/api/v1/targets", "/api/v1/findings", "/api/v1/risk-incidents"]) {
      expect(calledPaths).not.toContain(excludedPath);
    }
  });

  it("composes real widgets from Network Defense-valid sources only, honestly empty with no data", async () => {
    vi.spyOn(securityOperations, "getSummary").mockResolvedValue({
      period: "24h",
      canonical_assets: 0,
      critical_high_conditions: 2,
      active_correlations: 1,
      runtime_unhealthy_components: 0,
      active_targets: null,
      active_continuous_validation_policies: null,
      validations_running: null,
      validations_blocked_in_period: null,
      validations_failed_in_period: null,
      drift_events_in_period: null,
    });
    vi.spyOn(securityOperations, "listChanges").mockResolvedValue([]);
    vi.spyOn(securityOperations, "listRuntimeComponents").mockResolvedValue([]);
    vi.spyOn(ddosApi, "listIncidents").mockResolvedValue([]);
    vi.spyOn(behaviorApi, "listDetections").mockResolvedValue([]);
    vi.spyOn(networkSecurityApi, "getInventory").mockResolvedValue([]);
    vi.spyOn(investigationsApi, "getInvestigationPosture").mockResolvedValue({
      open_cases: 0,
      acknowledged_cases: 0,
      investigating_cases: 0,
      resolved_cases: 0,
      critical_cases: 0,
      high_cases: 0,
      multi_domain_cases: 0,
      total_active: 0,
    });
    vi.spyOn(investigationsApi, "listInvestigations").mockResolvedValue([]);

    const spec = await networkDashboardAggregator.load({ timeRange: "24h", filters: {} });

    expect(spec.id).toBe("network-defense-overview");
    const conditionsKpi = spec.widgets.find(
      (w) => w.type === "kpi" && w.viewModel.id === "conditions"
    );
    expect(conditionsKpi).toBeDefined();
    if (conditionsKpi?.type === "kpi") {
      expect(conditionsKpi.viewModel.value).toBe(2);
    }
    // No Full-only KPI id should ever appear.
    const kpiIds = spec.widgets.filter((w) => w.type === "kpi").map((w) => w.viewModel.id);
    for (const fullOnlyId of ["targets", "assets", "critical-findings", "critical-vulns", "risk-profiles"]) {
      expect(kpiIds).not.toContain(fullOnlyId);
    }
  });
});
