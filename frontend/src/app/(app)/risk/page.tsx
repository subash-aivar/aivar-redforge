"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { RiskIncident, Finding } from "@/lib/types";

export default function RiskPage() {
  const [incidents, setIncidents] = useState<RiskIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [findingsMap, setFindingsMap] = useState<Record<string, Finding[]>>({});
  const [findingsLoading, setFindingsLoading] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<RiskIncident[]>("/api/v1/risk-incidents")
      .then((data) => setIncidents(Array.isArray(data) ? data : []))
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
        r.finding_ids.slice(0, 5).map((fid) =>
          api.get<Finding>(`/api/v1/findings/${fid}`).catch(() => null)
        )
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

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Risk Intelligence</h1>
      <p className="mt-1 text-sm text-gray-400">
        Correlated security risk incidents. Click an incident to inspect related findings.
      </p>

      {loading ? (
        <div className="mt-8 text-gray-500">Loading risk data...</div>
      ) : sorted.length === 0 ? (
        <div className="mt-8 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
          <p className="text-gray-400">No risk incidents.</p>
          <p className="mt-2 text-sm text-gray-500">
            Risk incidents are generated from correlated findings across campaigns.
          </p>
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {sorted.map((r) => {
            const isOpen = expanded === r.id;
            const findings = findingsMap[r.id] ?? null;
            const loadingFindings = findingsLoading === r.id;
            return (
              <div key={r.id} className="rounded-xl border border-gray-800 bg-gray-900">
                <button
                  onClick={() => toggleIncident(r)}
                  className="w-full text-left p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-600">{isOpen ? "▼" : "▶"}</span>
                      <h3 className="font-medium text-white">{r.title}</h3>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-sm font-bold text-red-400">
                        {r.score.toFixed(1)}
                      </span>
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
                      {r.finding_ids.length > 5 && (
                        <span className="text-gray-600"> — showing first 5</span>
                      )}
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
                          <div
                            key={f.id}
                            className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium text-gray-200">
                                {f.title}
                              </span>
                              <SeverityBadge severity={f.severity} />
                            </div>
                            <div className="mt-1 flex gap-3 text-xs text-gray-600">
                              <span>Score: {f.risk_score.toFixed(1)}</span>
                              <span>{f.status}</span>
                              <span>Evidence: {f.evidence_ids.length}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    {r.affected_targets.length > 0 && (
                      <div className="mt-3">
                        <div className="text-xs font-medium text-gray-400 mb-1">
                          Affected targets
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {r.affected_targets.map((t) => (
                            <span
                              key={t}
                              className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400 font-mono"
                            >
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
      )}
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
