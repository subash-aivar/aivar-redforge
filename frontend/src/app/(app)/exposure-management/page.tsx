"use client";

import { useCallback, useEffect, useState } from "react";
import {
  getSecurityConditionSummary,
  listSecurityConditions,
  resolveSecurityCondition,
  type SecurityCondition,
  type SecurityConditionSummary,
} from "@/lib/securityConditions";
import { InvestigationDrawer } from "@/components/cc";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-950 text-red-400",
  high: "bg-orange-950 text-orange-400",
  medium: "bg-amber-950 text-amber-400",
  low: "bg-yellow-950 text-yellow-300",
  informational: "bg-gray-800 text-gray-400",
};

function severityBadge(severity: string): string {
  return SEVERITY_STYLES[severity] ?? "bg-gray-800 text-gray-400";
}

function displayEnum(value: string | undefined): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

function SummaryCard({ label, count }: { label: string; count: number }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-2xl font-bold text-white">{count}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

export default function ExposureManagementPage() {
  const [summary, setSummary] = useState<SecurityConditionSummary | null>(null);
  const [conditions, setConditions] = useState<SecurityCondition[] | null>(null);
  const [selected, setSelected] = useState<SecurityCondition | null>(null);
  const [error, setError] = useState("");
  const [resolving, setResolving] = useState(false);

  const [evidenceState, setEvidenceState] = useState("");
  const [severity, setSeverity] = useState("");
  const [sourceCategory, setSourceCategory] = useState("");
  const [lifecycle, setLifecycle] = useState("");

  const load = useCallback(() => {
    setError("");
    getSecurityConditionSummary()
      .then(setSummary)
      .catch(() => setError("UNAVAILABLE — failed to load exposure overview."));
    listSecurityConditions({
      evidence_state: evidenceState || undefined,
      severity: severity || undefined,
      source_category: sourceCategory || undefined,
    })
      .then((rows) =>
        setConditions(lifecycle ? rows.filter((c) => c.lifecycle === lifecycle) : rows)
      )
      .catch(() => setError("UNAVAILABLE — failed to load security conditions."));
  }, [evidenceState, severity, sourceCategory, lifecycle]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleResolve(id: string) {
    setResolving(true);
    try {
      const updated = await resolveSecurityCondition(id);
      setSelected(updated);
      load();
    } catch {
      setError("Failed to resolve condition.");
    } finally {
      setResolving(false);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Exposure Management</h1>
      <p className="mt-1 text-sm text-gray-400">
        Canonical, deterministic security conditions identified across discovered
        network and cloud assets — evidence-backed exposure context, not
        confirmed vulnerabilities or validated exploits. Evidence state
        distinguishes what was directly observed from what remains unvalidated.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <SummaryCard label="Observed" count={summary.by_evidence_state.observed ?? 0} />
          <SummaryCard label="Inferred" count={summary.by_evidence_state.inferred ?? 0} />
          <SummaryCard label="Validated" count={summary.by_evidence_state.validated ?? 0} />
          <SummaryCard label="Active" count={summary.by_lifecycle.active ?? 0} />
          <SummaryCard label="Resolved" count={summary.by_lifecycle.resolved ?? 0} />
        </div>
      ) : (
        <div className="mt-6 text-gray-400">Loading overview…</div>
      )}

      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={evidenceState}
          onChange={(e) => setEvidenceState(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All evidence states</option>
          <option value="observed">Observed</option>
          <option value="inferred">Inferred</option>
          <option value="validated">Validated</option>
        </select>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select
          value={sourceCategory}
          onChange={(e) => setSourceCategory(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All sources</option>
          <option value="network_discovery">Network discovery</option>
          <option value="cloud_configuration">Cloud configuration</option>
          <option value="identity_analysis">Identity analysis</option>
          <option value="manual_import">Manual import</option>
        </select>
        <select
          value={lifecycle}
          onChange={(e) => setLifecycle(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All lifecycle states</option>
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      {conditions === null ? (
        <div className="mt-6 text-gray-400">Loading conditions…</div>
      ) : conditions.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No security conditions match the current filters.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {conditions.map((c) => (
            <button
              key={c.id}
              onClick={() => setSelected(c)}
              className="block w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-700"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-400">
                  {c.stable_rule_id}
                </span>
                <span className={`rounded px-2 py-0.5 text-xs ${severityBadge(c.severity)}`}>
                  {displayEnum(c.severity)}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {displayEnum(c.evidence_state)}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {c.lifecycle === "resolved" ? "RESOLVED" : "ACTIVE"}
                </span>
              </div>
              <div className="mt-2 text-sm font-medium text-gray-200">{c.title}</div>
              <div className="mt-1 text-xs text-gray-500">
                Asset {c.affected_asset_id} · Source {displayEnum(c.source_category)} · Last
                observed {new Date(c.last_observed_at).toLocaleString()}
              </div>
            </button>
          ))}
        </div>
      )}

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.title ?? ""}
        subtitle={selected ? displayEnum(selected.severity) : undefined}
        entityId={selected?.id}
        fields={
          selected
            ? [
                { label: "Rule ID", value: <span className="font-mono">{selected.stable_rule_id}</span> },
                { label: "Affected asset", value: selected.affected_asset_id },
                { label: "Evidence state", value: displayEnum(selected.evidence_state) },
                {
                  label: "Severity",
                  value: (
                    <span className={`rounded px-2 py-0.5 text-xs ${severityBadge(selected.severity)}`}>
                      {displayEnum(selected.severity)}
                    </span>
                  ),
                },
                { label: "Source", value: displayEnum(selected.source_category) },
                { label: "Summary", value: selected.summary },
                ...(selected.remediation
                  ? [{ label: "Remediation", value: selected.remediation }]
                  : []),
                ...(selected.canonical_references.length > 0
                  ? [{ label: "References", value: selected.canonical_references.join(", ") }]
                  : []),
                ...(selected.evidence.length > 0
                  ? [
                      {
                        label: "Evidence",
                        value: (
                          <div className="space-y-1">
                            {selected.evidence.map((e, i) => (
                              <div key={i} className="rounded bg-gray-950 px-2 py-1 font-mono text-xs text-gray-400">
                                {e.label}: {e.value}
                                {e.truncated === "true" ? " (truncated)" : ""}
                              </div>
                            ))}
                          </div>
                        ),
                      },
                    ]
                  : []),
                {
                  label: "First observed",
                  value: new Date(selected.first_observed_at).toLocaleString(),
                },
                {
                  label: "Last observed",
                  value: new Date(selected.last_observed_at).toLocaleString(),
                },
                {
                  label: "Lifecycle",
                  value: selected.lifecycle === "resolved" ? "RESOLVED" : "ACTIVE",
                },
                ...(selected.lifecycle === "active"
                  ? [
                      {
                        label: "Actions",
                        value: (
                          <button
                            type="button"
                            onClick={() => handleResolve(selected.id)}
                            disabled={resolving}
                            className="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
                          >
                            {resolving ? "Resolving…" : "Resolve"}
                          </button>
                        ),
                      },
                    ]
                  : []),
              ]
            : []
        }
      />
    </div>
  );
}
