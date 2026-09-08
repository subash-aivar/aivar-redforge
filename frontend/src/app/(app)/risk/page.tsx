"use client";

import { useState } from "react";
import { useEffect } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  RelatedEntitiesPanel,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { api } from "@/lib/api";
import type { RiskIncident, RiskIncidentList, Finding } from "@/lib/types";
import {
  getRiskProfileCoverage,
  listRiskProfiles,
  type RiskProfile,
} from "@/lib/riskEngine";

/**
 * Risk Intelligence operational landing page: coverage-by-status (open,
 * acknowledged, mitigated, accepted, closed enterprise risk profiles — real
 * `/api/v1/risk-profiles` data, previously never surfaced anywhere in the
 * frontend), the profile register itself, and the pre-existing correlated
 * risk-incident feed below it as "current activity".
 */
export default function RiskPage() {
  const coverage = useAsync(() => getRiskProfileCoverage(), []);
  const profiles = useAsync(() => listRiskProfiles({ limit: 200 }), []);
  const [selected, setSelected] = useState<RiskProfile | null>(null);

  const columns: ConsoleColumn<RiskProfile>[] = [
    {
      key: "subject",
      header: "Subject",
      width: "28%",
      render: (r) => <span className="text-gray-200">{r.subject_reference}</span>,
    },
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    {
      key: "score",
      header: "Composite Score",
      width: "16%",
      render: (r) => (
        <span className="tabular-nums text-gray-300">
          {r.composite_score === null ? "—" : r.composite_score.toFixed(2)}
        </span>
      ),
    },
    { key: "contributions", header: "Contributions", width: "14%", render: (r) => r.contributions.length },
    {
      key: "updated",
      header: "Updated",
      width: "18%",
      render: (r) => <span className="text-gray-500">{new Date(r.updated_at).toLocaleString()}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Risk Intelligence"
        subtitle="Enterprise risk profile coverage and correlated risk incidents"
        actions={
          <button
            type="button"
            onClick={() => {
              coverage.reload();
              profiles.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <Panel title="Coverage" className="mb-6">
        <AsyncContent state={coverage}>
          {(c) => (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <KpiTile label="Open" value={c.open} tone="danger" />
              <KpiTile label="Acknowledged" value={c.acknowledged} tone="warning" />
              <KpiTile label="Mitigated" value={c.mitigated} tone="ok" />
              <KpiTile label="Accepted" value={c.accepted} />
              <KpiTile label="Closed" value={c.closed} />
            </div>
          )}
        </AsyncContent>
      </Panel>

      <Panel title="Risk Profile Register" className="mb-8">
        <AsyncContent state={profiles} empty={(p) => p.items.length === 0} emptyLabel="No enterprise risk profiles yet.">
          {(p) => (
            <DataConsole
              columns={columns}
              rows={p.items}
              rowKey={(r) => r.profile_id}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No enterprise risk profiles yet."
            />
          )}
        </AsyncContent>
      </Panel>

      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
        Correlated Risk Incidents
      </h2>
      <RiskIncidentFeed />

      {selected && (
        <InvestigationDrawer
          open
          title={selected.subject_reference}
          subtitle={`Profile ${selected.profile_id}`}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Status", value: selected.status },
            {
              label: "Composite Score",
              value: selected.composite_score === null ? "—" : selected.composite_score.toFixed(2),
            },
            { label: "Weight Profile", value: selected.weight_profile_id ?? "—" },
            { label: "Created", value: new Date(selected.created_at).toLocaleString() },
            { label: "Updated", value: new Date(selected.updated_at).toLocaleString() },
            {
              label: "Accepted Expires",
              value: selected.accepted_expires_at ? new Date(selected.accepted_expires_at).toLocaleString() : "—",
            },
            {
              label: "Contributions",
              value:
                selected.contributions.length === 0 ? (
                  "—"
                ) : (
                  <div className="space-y-1.5">
                    {selected.contributions.map((c, i) => (
                      <div key={i} className="rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-300">{c.dimension}</span>
                          <span className="tabular-nums text-gray-400">{c.normalized_score.toFixed(2)}</span>
                        </div>
                        <div className="mt-0.5 text-gray-600">{c.source_context} · {c.source_id}</div>
                      </div>
                    ))}
                  </div>
                ),
            },
          ]}
        />
      )}
    </>
  );
}

function RiskIncidentFeed() {
  const [incidents, setIncidents] = useState<RiskIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [findingsMap, setFindingsMap] = useState<Record<string, Finding[]>>({});
  const [findingsLoading, setFindingsLoading] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<RiskIncidentList>("/api/v1/risk-incidents")
      .then((data) => setIncidents(Array.isArray(data?.items) ? data.items : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function toggleIncident(r: RiskIncident) {
    if (expanded === r.id) {
      setExpanded(null);
      return;
    }
    setExpanded(r.id);
    if (findingsMap[r.id] !== undefined || r.finding_ids.length === 0) return;
    setFindingsLoading(r.id);
    try {
      const results = await Promise.all(
        r.finding_ids.slice(0, 5).map((fid) => api.get<Finding>(`/api/v1/findings/${fid}`).catch(() => null))
      );
      setFindingsMap((prev) => ({
        ...prev,
        [r.id]: results.filter((f): f is Finding => f !== null),
      }));
    } finally {
      setFindingsLoading(null);
    }
  }

  const sorted = [...incidents].sort((a, b) => b.score - a.score);

  if (loading) return <div className="text-gray-500">Loading risk data...</div>;
  if (sorted.length === 0) {
    return (
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
        <p className="text-gray-400">No risk incidents.</p>
        <p className="mt-2 text-sm text-gray-500">
          Risk incidents are generated from correlated findings across campaigns.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {sorted.map((r) => {
        const isOpen = expanded === r.id;
        const findings = findingsMap[r.id] ?? null;
        const loadingFindings = findingsLoading === r.id;
        return (
          <div key={r.id} className="rounded-xl border border-gray-800 bg-gray-900">
            <button onClick={() => toggleIncident(r)} className="w-full text-left p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-600">{isOpen ? "▼" : "▶"}</span>
                  <h3 className="font-medium text-white">{r.title}</h3>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-sm font-bold text-red-400">{r.score.toFixed(1)}</span>
                  <SeverityBadge severity={r.severity} />
                </div>
              </div>
              <div className="mt-2 flex gap-4 text-xs text-gray-500 ml-4">
                <span>Status: {r.status}</span>
                <span>Affected targets: {r.affected_targets.length}</span>
                <span>Related findings: {r.finding_ids.length}</span>
              </div>
            </button>

            {isOpen && (
              <div className="border-t border-gray-800 px-4 pb-4">
                <div className="mt-3 text-xs font-medium text-gray-400 mb-2">
                  Related findings ({r.finding_ids.length})
                  {r.finding_ids.length > 5 && <span className="text-gray-600"> — showing first 5</span>}
                </div>
                {r.finding_ids.length === 0 ? (
                  <div className="text-xs text-gray-600">No related findings linked.</div>
                ) : loadingFindings ? (
                  <div className="text-xs text-gray-500">Loading findings…</div>
                ) : findings === null ? (
                  <div className="text-xs text-gray-600">Findings not loaded.</div>
                ) : findings.length === 0 ? (
                  <div className="text-xs text-gray-600">Findings could not be retrieved.</div>
                ) : (
                  <div className="space-y-2">
                    {findings.map((f) => (
                      <div key={f.id} className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-gray-200">{f.title}</span>
                          <SeverityBadge severity={f.severity} />
                        </div>
                        <div className="mt-1 flex items-center justify-between text-xs text-gray-600">
                          <div className="flex gap-3">
                            <span>Score: {f.risk_score.toFixed(1)}</span>
                            <span>{f.status}</span>
                            <span>Evidence: {f.evidence_ids.length}</span>
                          </div>
                          <RelatedEntitiesPanel
                            title=""
                            links={[{ label: "View in Findings →", href: `/findings?highlight=${f.id}` }]}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {r.affected_targets.length > 0 && (
                  <div className="mt-3">
                    <div className="text-xs font-medium text-gray-400 mb-1">Affected targets</div>
                    <div className="flex flex-wrap gap-2">
                      {r.affected_targets.map((t) => (
                        <span key={t} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400 font-mono">
                          {t.slice(0, 16)}…
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-950 text-red-400 border-red-800",
    high: "bg-orange-950 text-orange-400 border-orange-800",
    medium: "bg-yellow-950 text-yellow-400 border-yellow-800",
    low: "bg-blue-950 text-blue-400 border-blue-800",
  };
  return (
    <span
      className={`rounded border px-2 py-0.5 text-xs font-medium ${
        colors[severity] ?? "bg-gray-800 text-gray-400 border-gray-700"
      }`}
    >
      {severity}
    </span>
  );
}
