"use client";

import Link from "next/link";
import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  getAgentDeviations,
  getAsset,
  getInventoryDashboard,
  getRiskRegister,
  getShadowDiscoveryReport,
  getSupplyChainIntegrity,
  triageAlert,
  type AgentDeviationRow,
  type AIInventoryAssetSummary,
  type AISystemAsset,
  type RiskRegisterEntry,
  type ShadowAlertSummary,
  type SupplyChainModelRow,
} from "@/lib/ai-posture";

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-gray-400",
};

/**
 * AI Security Operations Center (ai_posture bounded context).
 *
 * Repository audit (Slice 4) found three real dashboard/report
 * endpoints with zero frontend consumer before this: `dashboards/
 * risk-register`, `reports/supply-chain-integrity`,
 * `reports/agent-deviations` (verified against
 * `ai_posture/application/projections/read_models.py` and the event
 * handlers in `projection_service.py` that populate them — every
 * field below is copied from those handlers, not guessed). All three
 * share a real `asset_id` key with the existing AI Asset Inventory,
 * which this page uses to build a genuine per-asset relationship view
 * (Risk score, Supply-chain provenance, Agent deviations for the
 * asset just clicked) — the same `asset_id` the backend itself joins
 * on, not an invented association.
 *
 * `ai_agent_governance` (a separate bounded context, `/ai-governance`
 * page) is NOT this page's "Agent Deviations" — that field name
 * collision is coincidental; `agent_deviations` here is confirmed to
 * live in `ai_posture`.
 */
export default function AIPosturePage() {
  const inventory = useAsync(() => getInventoryDashboard(), []);
  const shadow = useAsync(() => getShadowDiscoveryReport(), []);
  const riskRegister = useAsync(() => getRiskRegister(), []);
  const supplyChain = useAsync(() => getSupplyChainIntegrity(), []);
  const deviations = useAsync(() => getAgentDeviations(), []);

  const [selectedAlert, setSelectedAlert] = useState<ShadowAlertSummary | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<AIInventoryAssetSummary | null>(null);
  const [assetDetail, setAssetDetail] = useState<AISystemAsset | null>(null);
  const [assetError, setAssetError] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function refreshAll() {
    inventory.reload();
    shadow.reload();
    riskRegister.reload();
    supplyChain.reload();
    deviations.reload();
  }

  async function handleTriage(alert: ShadowAlertSummary) {
    const notes = window.prompt("Triage notes (optional):", "") ?? "";
    setBusy(true);
    setActionError(null);
    try {
      await triageAlert(alert.alert_id, "analyst", notes);
      setSelectedAlert(null);
      shadow.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Triage failed");
    } finally {
      setBusy(false);
    }
  }

  async function openAsset(asset: AIInventoryAssetSummary) {
    setSelectedAsset(asset);
    setAssetDetail(null);
    setAssetError("");
    try {
      setAssetDetail(await getAsset(asset.asset_id));
    } catch {
      setAssetError("Failed to load asset detail.");
    }
  }

  const assetColumns: ConsoleColumn<AIInventoryAssetSummary>[] = [
    { key: "id", header: "Asset", width: "34%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.asset_id.slice(0, 14)}…</span>
    ) },
    { key: "kind", header: "AI System Kind", width: "33%", render: (r) => r.ai_system_kind || "—" },
    { key: "state", header: "Lifecycle State", width: "33%", render: (r) => (
      <StatusPill status={r.lifecycle_state} />
    ) },
  ];

  const alertColumns: ConsoleColumn<ShadowAlertSummary>[] = [
    { key: "id", header: "Alert", width: "34%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.alert_id.slice(0, 14)}…</span>
    ) },
    { key: "source", header: "Discovery Source", width: "33%", render: (r) => r.discovery_source },
    { key: "fingerprint", header: "Fingerprint", width: "33%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-500">{r.fingerprint_hash.slice(0, 12)}…</span>
    ) },
  ];

  const riskColumns: ConsoleColumn<RiskRegisterEntry>[] = [
    { key: "asset", header: "Asset", width: "34%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.asset_id.slice(0, 14)}…</span>
    ) },
    { key: "score", header: "Composite Score", width: "22%", render: (r) => (
      <span className="tabular-nums text-gray-200">{r.composite_score.toFixed(2)}</span>
    ) },
    { key: "stale", header: "Freshness", width: "22%", render: (r) => (
      <StatusPill status={r.is_stale ? "stale" : "current"} />
    ) },
    { key: "computed", header: "Computed", width: "22%", render: (r) => (
      <span className="text-gray-500">{fmtTime(r.computed_at)}</span>
    ) },
  ];

  const supplyChainColumns: ConsoleColumn<SupplyChainModelRow>[] = [
    { key: "asset", header: "Asset", width: "22%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.asset_id.slice(0, 14)}…</span>
    ) },
    { key: "status", header: "Integrity", width: "22%", render: (r) => <StatusPill status={r.integrity_status} /> },
    { key: "tier", header: "Verification Tier", width: "20%", render: (r) => r.tier_label },
    { key: "method", header: "Method", width: "20%", render: (r) => r.verification_method },
    {
      key: "link",
      header: "",
      width: "16%",
      render: (r) => (
        <Link
          href={`/ai-supply-chain?highlight=${r.provenance_id}`}
          className="text-[11px] font-medium text-red-400 hover:text-red-300"
        >
          Verify / Reset →
        </Link>
      ),
    },
  ];

  const deviationColumns: ConsoleColumn<AgentDeviationRow>[] = [
    { key: "asset", header: "Agent Asset", width: "26%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.asset_id.slice(0, 14)}…</span>
    ) },
    { key: "type", header: "Deviation Type", width: "26%", render: (r) => r.deviation_type },
    { key: "severity", header: "Severity", width: "24%", render: (r) => (
      <span className={SEVERITY_TONE[r.severity.toLowerCase()] ?? "text-gray-400"}>{r.severity}</span>
    ) },
    { key: "review", header: "Review State", width: "24%", render: (r) => <StatusPill status={r.review_state} /> },
  ];

  const relatedForAsset = (assetId: string) => {
    const riskEntry = riskRegister.data?.entries.find((e) => e.asset_id === assetId);
    const scModels = supplyChain.data?.models.filter((m) => m.asset_id === assetId) ?? [];
    const devs = deviations.data?.deviations.filter((d) => d.asset_id === assetId) ?? [];
    return { riskEntry, scModels, devs };
  };

  return (
    <>
      <PageHeader
        title="AI Security Operations Center"
        subtitle="AI asset inventory, shadow-AI discovery, risk register, supply-chain integrity, and agent deviations"
        actions={
          <button
            type="button"
            onClick={refreshAll}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-4">
        <AsyncContent
          state={inventory}
          empty={(d) => !!d.empty}
          emptyLabel="No AI assets registered yet."
        >
          {(data) => (
            <>
              <KpiTile label="Registered AI Assets" value={data.assets.length} />
              <KpiTile
                label="Coverage Scope"
                value={data.coverage_scope}
                hint={data.last_scan_at ? `Last scan ${fmtTime(data.last_scan_at)}` : "No scan yet"}
              />
            </>
          )}
        </AsyncContent>
        {shadow.data && !shadow.data.empty && (
          <KpiTile
            label="Shadow AI Alerts"
            value={shadow.data.alerts.length}
            tone={shadow.data.alerts.length > 0 ? "danger" : "ok"}
          />
        )}
        {deviations.data && !deviations.data.empty && (
          <KpiTile
            label="Agent Deviations"
            value={deviations.data.deviations.length}
            tone={deviations.data.deviations.length > 0 ? "warning" : "ok"}
          />
        )}
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Panel title="AI Asset Inventory">
          <AsyncContent
            state={inventory}
            empty={(d) => !!d.empty || d.assets.length === 0}
            emptyLabel="No AI assets registered yet."
          >
            {(data) => (
              <DataConsole
                columns={assetColumns}
                rows={data.assets}
                rowKey={(r) => r.asset_id}
                onRowClick={(r) => openAsset(r)}
                selectedKey={selectedAsset?.asset_id ?? null}
                emptyLabel="No AI assets registered yet."
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Shadow AI Discovery">
          <AsyncContent
            state={shadow}
            empty={(d) => !!d.empty || d.alerts.length === 0}
            emptyLabel="No shadow AI alerts."
          >
            {(data) => (
              <DataConsole
                columns={alertColumns}
                rows={data.alerts}
                rowKey={(r) => r.alert_id}
                onRowClick={(r) => setSelectedAlert(r)}
                selectedKey={selectedAlert?.alert_id ?? null}
                emptyLabel="No shadow AI alerts."
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Panel title="AI Risk Register">
          <AsyncContent
            state={riskRegister}
            empty={(d) => !!d.empty || d.entries.length === 0}
            emptyLabel="No AI risk scores computed yet."
          >
            {(data) => (
              <DataConsole
                columns={riskColumns}
                rows={data.entries}
                rowKey={(r) => r.asset_id}
                emptyLabel="No AI risk scores computed yet."
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="AI Supply Chain Integrity">
          <AsyncContent
            state={supplyChain}
            empty={(d) => !!d.empty || d.models.length === 0}
            emptyLabel="No model provenance facts recorded yet."
          >
            {(data) => (
              <DataConsole
                columns={supplyChainColumns}
                rows={data.models}
                rowKey={(r) => r.provenance_id}
                emptyLabel="No model provenance facts recorded yet."
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Agent Deviations">
          <AsyncContent
            state={deviations}
            empty={(d) => !!d.empty || d.deviations.length === 0}
            emptyLabel="No agent deviations recorded yet."
          >
            {(data) => (
              <DataConsole
                columns={deviationColumns}
                rows={data.deviations}
                rowKey={(r) => r.deviation_id}
                emptyLabel="No agent deviations recorded yet."
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <InvestigationDrawer
        open={selectedAlert !== null}
        onClose={() => {
          setSelectedAlert(null);
          setActionError(null);
        }}
        title={selectedAlert ? `Alert ${selectedAlert.alert_id.slice(0, 14)}…` : ""}
        subtitle={selectedAlert?.discovery_source}
        entityId={selectedAlert?.alert_id}
        fields={
          selectedAlert
            ? [
                { label: "Discovery Source", value: selectedAlert.discovery_source },
                { label: "Fingerprint Hash", value: selectedAlert.fingerprint_hash },
                ...(actionError
                  ? [{ label: "Action Error", value: <span className="text-red-400">{actionError}</span> }]
                  : []),
                {
                  label: "Actions",
                  value: (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => selectedAlert && handleTriage(selectedAlert)}
                      className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                    >
                      Triage Alert
                    </button>
                  ),
                },
              ]
            : []
        }
      />

      {selectedAsset && (
        <InvestigationDrawer
          open
          onClose={() => setSelectedAsset(null)}
          title={selectedAsset.ai_system_kind || "AI Asset"}
          subtitle={selectedAsset.lifecycle_state}
          entityId={selectedAsset.asset_id}
          fields={
            assetError
              ? [{ label: "Error", value: assetError }]
              : !assetDetail
                ? [{ label: "Loading", value: "Fetching asset detail…" }]
                : (() => {
                    const { riskEntry, scModels, devs } = relatedForAsset(selectedAsset.asset_id);
                    return [
                      { label: "Registration Status", value: <StatusPill status={assetDetail.registration_status} /> },
                      { label: "Lifecycle State", value: <StatusPill status={assetDetail.lifecycle_state} /> },
                      { label: "Data Sensitivity", value: assetDetail.data_sensitivity },
                      { label: "Owner", value: assetDetail.owner_id ?? "Unassigned" },
                      {
                        label: "Risk Score",
                        value: riskEntry
                          ? `${riskEntry.composite_score.toFixed(2)} (${riskEntry.is_stale ? "stale" : "current"})`
                          : "Not yet computed",
                      },
                      {
                        label: `Supply Chain Provenance (${scModels.length})`,
                        value:
                          scModels.length === 0 ? (
                            "—"
                          ) : (
                            <div className="space-y-1">
                              {scModels.map((m) => (
                                <div key={m.provenance_id} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs">
                                  <span className="text-gray-300">{m.integrity_status}</span>
                                  <span className="ml-2 text-gray-600">{m.tier_label}</span>
                                </div>
                              ))}
                            </div>
                          ),
                      },
                      {
                        label: `Agent Deviations (${devs.length})`,
                        value:
                          devs.length === 0 ? (
                            "—"
                          ) : (
                            <div className="space-y-1">
                              {devs.map((d) => (
                                <div key={d.deviation_id} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs">
                                  <span className={SEVERITY_TONE[d.severity.toLowerCase()] ?? "text-gray-300"}>
                                    {d.deviation_type}
                                  </span>
                                  <span className="ml-2 text-gray-600">{d.review_state}</span>
                                </div>
                              ))}
                            </div>
                          ),
                      },
                    ];
                  })()
          }
        />
      )}
    </>
  );
}
