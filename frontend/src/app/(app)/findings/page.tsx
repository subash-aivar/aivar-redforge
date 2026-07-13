"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

interface EvidenceItem {
  id: string;
  attack_type: string;
  result: string;
  confidence: number;
  request_url: string;
  response_status: number;
  duration_ms: number;
  finalized: boolean;
}

interface EvidenceListResponse {
  items: EvidenceItem[];
  total: number;
  limit: number;
  offset: number;
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [evidenceMap, setEvidenceMap] = useState<Record<string, EvidenceItem[]>>({});
  const [evidenceLoading, setEvidenceLoading] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Finding[]>("/api/v1/findings")
      .then((data) => setFindings(Array.isArray(data) ? data : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function toggleFinding(f: Finding) {
    if (expanded === f.id) {
      setExpanded(null);
      return;
    }
    setExpanded(f.id);
    if (evidenceMap[f.id]) return;
    setEvidenceLoading(f.id);
    try {
      const resp = await api.get<EvidenceListResponse>(
        `/api/v1/evidence?run_id=${encodeURIComponent(f.run_id)}&limit=20&offset=0`
      );
      setEvidenceMap((prev) => ({ ...prev, [f.id]: resp.items }));
    } catch {
      setEvidenceMap((prev) => ({ ...prev, [f.id]: [] }));
    } finally {
      setEvidenceLoading(null);
    }
  }

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Security Findings</h1>
      <p className="mt-1 text-sm text-gray-400">
        Vulnerabilities discovered through AI red-team validation. Click a finding to inspect evidence.
      </p>

      {loading ? (
        <div className="mt-8 text-gray-500">Loading findings...</div>
      ) : sorted.length === 0 ? (
        <div className="mt-8 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
          <p className="text-gray-400">No findings yet.</p>
          <p className="mt-2 text-sm text-gray-500">
            Run a red-team campaign to discover security vulnerabilities.
          </p>
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {sorted.map((f) => {
            const isOpen = expanded === f.id;
            const evidence = evidenceMap[f.id] ?? null;
            const loadingEvidence = evidenceLoading === f.id;
            return (
              <div key={f.id} className="rounded-xl border border-gray-800 bg-gray-900">
                <button
                  onClick={() => toggleFinding(f)}
                  className="w-full text-left p-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-600">{isOpen ? "▼" : "▶"}</span>
                        <h3 className="font-medium text-white">{f.title}</h3>
                      </div>
                      <p className="mt-1 text-sm text-gray-400 line-clamp-2 ml-4">
                        {f.description}
                      </p>
                    </div>
                    <div className="ml-4 flex flex-col items-end gap-1 shrink-0">
                      <SeverityBadge severity={f.severity} />
                      <span
                        className={`text-xs ${
                          f.status === "open" ? "text-yellow-400" : "text-gray-500"
                        }`}
                      >
                        {f.status}
                      </span>
                    </div>
                  </div>
                  {f.recommendation && (
                    <div className="mt-3 rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-400 ml-4">
                      <span className="font-medium text-gray-300">Recommendation: </span>
                      {f.recommendation}
                    </div>
                  )}
                  <div className="mt-2 flex gap-4 text-xs text-gray-600 ml-4">
                    <span>Risk Score: {f.risk_score.toFixed(1)}</span>
                    <span>Evidence: {f.evidence_ids.length} items</span>
                    <span>Target: {f.target_id.slice(0, 8)}…</span>
                  </div>
                </button>

                {isOpen && (
                  <div className="border-t border-gray-800 px-4 pb-4">
                    <div className="mt-3 text-xs font-medium text-gray-400 mb-2">
                      Evidence ({f.evidence_ids.length} items · run {f.run_id.slice(0, 12)}…)
                    </div>
                    {loadingEvidence ? (
                      <div className="text-xs text-gray-500">Loading evidence…</div>
                    ) : evidence === null ? (
                      <div className="text-xs text-gray-600">Evidence not loaded.</div>
                    ) : evidence.length === 0 ? (
                      <div className="text-xs text-gray-600">No evidence records for this run.</div>
                    ) : (
                      <div className="space-y-2">
                        {evidence.map((ev) => (
                          <div
                            key={ev.id}
                            className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium text-gray-300">
                                {ev.attack_type}
                              </span>
                              <div className="flex items-center gap-2">
                                <ResultChip result={ev.result} />
                                <span className="text-xs text-gray-600">
                                  {(ev.confidence * 100).toFixed(0)}% conf
                                </span>
                                <span className="text-xs text-gray-600">{ev.duration_ms}ms</span>
                              </div>
                            </div>
                            {ev.request_url && (
                              <div className="mt-1 text-xs text-gray-600 truncate">
                                {ev.request_url}
                              </div>
                            )}
                            <div className="mt-0.5 flex gap-3 text-xs text-gray-700">
                              <span>HTTP {ev.response_status}</span>
                              <span>{ev.finalized ? "finalized" : "draft"}</span>
                            </div>
                          </div>
                        ))}
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
    informational: "bg-gray-800 text-gray-400 border-gray-700",
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

function ResultChip({ result }: { result: string }) {
  const colors: Record<string, string> = {
    success: "text-red-400",
    failure: "text-green-400",
    error: "text-gray-500",
  };
  return (
    <span className={`text-xs font-medium ${colors[result] ?? "text-gray-400"}`}>
      {result}
    </span>
  );
}
