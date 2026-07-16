"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  getInvestigationPosture,
  listInvestigations,
  acknowledgeInvestigation,
  startInvestigation,
  severityColor,
  confidenceColor,
  statusColor,
  domainColor,
  domainLabel,
  formatTs,
  type InvestigationPosture,
  type InvestigationCase,
} from "@/lib/investigations";

// ── Sub-components ────────────────────────────────────────────────────────────

function MetricTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className={`text-3xl font-bold ${accent ?? "text-white"}`}>{value}</div>
      <div className="mt-1 text-sm font-semibold text-gray-300">{label}</div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${severityColor(severity)}`}>
      {severity}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${confidenceColor(confidence)}`}>
      {confidence.replace("_", " ")}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(status)}`}>
      {status}
    </span>
  );
}

function DomainTag({ domain }: { domain: string }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-xs ${domainColor(domain)}`}>
      {domainLabel(domain)}
    </span>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function InvestigationsPage() {
  const [posture, setPosture] = useState<InvestigationPosture | null>(null);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actioning, setActioning] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [p, c] = await Promise.all([
        getInvestigationPosture(),
        listInvestigations({
          status: statusFilter || undefined,
          severity: severityFilter || undefined,
          limit: 100,
        }),
      ]);
      setPosture(p);
      setCases(c);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load investigations");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter]);

  useEffect(() => { load(); }, [load]);

  async function handleAcknowledge(caseId: string) {
    setActioning(caseId);
    try {
      await acknowledgeInvestigation(caseId);
      await load();
    } catch {
      // ignore — reload on next refresh
    } finally {
      setActioning(null);
    }
  }

  async function handleStartInvestigation(caseId: string) {
    setActioning(caseId);
    try {
      await startInvestigation(caseId);
      await load();
    } catch {
      // ignore — reload on next refresh
    } finally {
      setActioning(null);
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Unified Threat Investigation</h1>
          <p className="mt-1 text-sm text-gray-400">
            Cross-domain security cases with deterministic, explainable correlation
          </p>
        </div>
        <button
          onClick={load}
          className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-900/20 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Posture tiles */}
      {posture && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          <MetricTile label="Open" value={posture.open_cases} accent="text-red-400" />
          <MetricTile label="Acknowledged" value={posture.acknowledged_cases} accent="text-yellow-400" />
          <MetricTile label="Investigating" value={posture.investigating_cases} accent="text-blue-400" />
          <MetricTile label="Resolved" value={posture.resolved_cases} accent="text-green-400" />
          <MetricTile label="Critical" value={posture.critical_cases} accent="text-red-300" />
          <MetricTile label="High" value={posture.high_cases} accent="text-orange-300" />
          <MetricTile label="Multi-Domain" value={posture.multi_domain_cases} accent="text-purple-300" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span className="self-center text-xs text-gray-500">
          {cases.length} case{cases.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Cases table */}
      {loading ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center text-sm text-gray-500">
          Loading investigations…
        </div>
      ) : cases.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center">
          <div className="text-4xl text-gray-600">⊕</div>
          <div className="mt-3 text-sm text-gray-400">No investigation cases found</div>
          <div className="mt-1 text-xs text-gray-600">
            Cases are opened automatically when the correlation worker detects cross-domain signals
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3">Case</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Domains</th>
                <th className="px-4 py-3">Evidence</th>
                <th className="px-4 py-3">First Observed</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-950">
              {cases.map((c) => (
                <tr key={c.id} className="hover:bg-gray-900/60">
                  <td className="px-4 py-3">
                    <Link
                      href={`/investigations/${c.id}`}
                      className="font-medium text-white hover:text-blue-400"
                    >
                      {c.title}
                    </Link>
                    <div className="mt-0.5 max-w-sm truncate text-xs text-gray-500">{c.summary}</div>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={c.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <ConfidenceBadge confidence={c.confidence} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(c.source_domains ?? []).map((d) => (
                        <DomainTag key={d} domain={d} />
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-300">{c.evidence_count}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{formatTs(c.first_observed_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      {c.status === "OPEN" && (
                        <button
                          onClick={() => handleAcknowledge(c.id)}
                          disabled={actioning === c.id}
                          className="rounded border border-yellow-800 bg-yellow-900/20 px-2 py-0.5 text-xs text-yellow-300 hover:bg-yellow-900/40 disabled:opacity-50"
                        >
                          Acknowledge
                        </button>
                      )}
                      {(c.status === "OPEN" || c.status === "ACKNOWLEDGED") && (
                        <button
                          onClick={() => handleStartInvestigation(c.id)}
                          disabled={actioning === c.id}
                          className="rounded border border-blue-800 bg-blue-900/20 px-2 py-0.5 text-xs text-blue-300 hover:bg-blue-900/40 disabled:opacity-50"
                        >
                          Investigate
                        </button>
                      )}
                      <Link
                        href={`/investigations/${c.id}`}
                        className="rounded border border-gray-700 bg-gray-800 px-2 py-0.5 text-xs text-gray-300 hover:bg-gray-700"
                      >
                        View
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Correlation explainer */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">
          About Correlation
        </div>
        <div className="mt-2 space-y-1 text-xs text-gray-400">
          <div>
            <span className="font-medium text-gray-300">Deterministic rules only</span> — no opaque AI
            scoring. Every case links to a specific rule (R01–R07) with a documented rationale.
          </div>
          <div>
            <span className="font-medium text-gray-300">Shared entity required</span> — temporal proximity
            alone never creates a case. A canonical IP address or resource ID must appear in both signals.
          </div>
          <div>
            <span className="font-medium text-gray-300">Cross-tenant isolation</span> — evidence from
            different organizations is never correlated. This invariant is enforced at every layer.
          </div>
        </div>
      </div>
    </div>
  );
}
