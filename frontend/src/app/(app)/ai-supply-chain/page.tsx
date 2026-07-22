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
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  listArtifacts,
  listRisks,
  scanArtifact,
  type ModelArtifact,
  type SupplyChainRisk,
} from "@/lib/aiSupplyChain";

export default function AISupplyChainPage() {
  const artifacts = useAsync(() => listArtifacts(), []);
  const risks = useAsync(() => listRisks(), []);
  const [selected, setSelected] = useState<ModelArtifact | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleScan(artifact: ModelArtifact) {
    setBusy(true);
    try {
      await scanArtifact(artifact.artifact_id);
      artifacts.reload();
    } finally {
      setBusy(false);
    }
  }

  const columns: ConsoleColumn<ModelArtifact>[] = [
    { key: "name", header: "Model Artifact", width: "24%", render: (r) => (
      <span className="text-gray-200">{r.name}</span>
    )},
    { key: "version", header: "Version", width: "10%", render: (r) => r.version },
    { key: "registry", header: "Registry", width: "14%", render: (r) => r.registry },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "risk", header: "Risk", width: "10%", render: (r) => (
      <span className={r.risk_score >= 7 ? "text-red-400 font-bold" : r.risk_score >= 4 ? "text-amber-400" : "text-gray-400"}>
        {r.risk_score.toFixed(1)}
      </span>
    )},
    { key: "vulns", header: "Vulns", width: "8%", render: (r) => (
      <span className={r.vulnerabilities > 0 ? "text-red-400" : "text-gray-500"}>{r.vulnerabilities}</span>
    )},
    { key: "scanned", header: "Last Scan", width: "14%", render: (r) => r.last_scanned_at?.slice(0,10) || "Never" },
  ];

  return (
    <>
      <PageHeader
        title="AI Supply Chain Security"
        subtitle="Model artifact inventory, dependency scanning, and supply chain risk"
      />

      <AsyncContent state={artifacts}>
        {(list) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Artifacts" value={list.length} />
              <KpiTile label="High Risk" value={list.filter(a => a.risk_score >= 7).length} tone="critical" />
              <KpiTile label="Vulnerabilities" value={list.reduce((s, a) => s + a.vulnerabilities, 0)} tone="high" />
              <KpiTile label="Unscanned" value={list.filter(a => !a.last_scanned_at).length} tone="warning" />
            </div>
            <DataConsole
              columns={columns}
              rows={list}
              rowKey={(r) => r.artifact_id}
              onRowClick={(r) => setSelected(r)}
              emptyMessage="No model artifacts tracked. Register ML models to monitor supply chain risk."
            />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer title={selected.name} onClose={() => setSelected(null)}>
          <div className="space-y-4 p-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div><span className="text-gray-500">Version:</span> <span className="text-gray-200">{selected.version}</span></div>
              <div><span className="text-gray-500">Registry:</span> <span className="text-gray-200">{selected.registry}</span></div>
              <div><span className="text-gray-500">Status:</span> <StatusPill status={selected.status} /></div>
              <div><span className="text-gray-500">Risk Score:</span> <span className="text-gray-200">{selected.risk_score.toFixed(1)}</span></div>
            </div>
            {selected.licenses.length > 0 && (
              <div>
                <span className="text-xs text-gray-500">Licenses:</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selected.licenses.map((l) => (
                    <span key={l} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{l}</span>
                  ))}
                </div>
              </div>
            )}
            {selected.dependencies.length > 0 && (
              <div>
                <span className="text-xs text-gray-500">Dependencies ({selected.dependencies.length}):</span>
                <div className="mt-1 max-h-32 overflow-y-auto rounded bg-gray-950 p-2 text-[11px] text-gray-400">
                  {selected.dependencies.join(", ")}
                </div>
              </div>
            )}
            <button
              onClick={() => handleScan(selected)}
              disabled={busy}
              className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
            >
              Scan Now
            </button>
          </div>
        </InvestigationDrawer>
      )}
    </>
  );
}
