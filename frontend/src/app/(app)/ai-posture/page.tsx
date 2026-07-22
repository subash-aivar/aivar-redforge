"use client";

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
  getInventoryDashboard,
  getShadowDiscoveryReport,
  triageAlert,
  type AIInventoryAssetSummary,
  type ShadowAlertSummary,
} from "@/lib/ai-posture";

export default function AIPosturePage() {
  const inventory = useAsync(() => getInventoryDashboard(), []);
  const shadow = useAsync(() => getShadowDiscoveryReport(), []);
  const [selectedAlert, setSelectedAlert] = useState<ShadowAlertSummary | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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

  return (
    <>
      <PageHeader
        title="AI Posture"
        subtitle="AI asset inventory, shadow-AI discovery, and risk visibility"
        actions={
          <button
            type="button"
            onClick={() => {
              inventory.reload();
              shadow.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <AsyncContent state={inventory} emptyLabel="No AI assets registered yet.">
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
        {shadow.data && (
          <KpiTile
            label="Shadow AI Alerts"
            value={shadow.data.alerts.length}
            tone={shadow.data.alerts.length > 0 ? "danger" : "ok"}
          />
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="AI Asset Inventory">
          <AsyncContent state={inventory} emptyLabel="No AI assets registered yet.">
            {(data) => (
              <DataConsole
                columns={assetColumns}
                rows={data.assets}
                rowKey={(r) => r.asset_id}
                emptyLabel="No AI assets registered yet."
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Shadow AI Discovery">
          <AsyncContent state={shadow} emptyLabel="No shadow AI alerts.">
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

      <InvestigationDrawer
        open={selectedAlert !== null}
        onClose={() => {
          setSelectedAlert(null);
          setActionError(null);
        }}
        title={selectedAlert ? `Alert ${selectedAlert.alert_id.slice(0, 14)}…` : ""}
        subtitle={selectedAlert?.discovery_source}
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
    </>
  );
}
