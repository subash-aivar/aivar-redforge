"use client";

import { useCallback, useEffect, useState } from "react";
import {
  evaluateCorrelations,
  getAssetExposureSummary,
  getAttackSurfaceSummary,
  listSecurityCorrelations,
  type AssetExposureSummary,
  type AttackSurfaceSummary,
  type SecurityCorrelation,
} from "@/lib/securityCorrelations";

function displayEnum(value: string | undefined | null): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

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

function SummaryCard({ label, count }: { label: string; count: number }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-2xl font-bold text-white">{count}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

export default function AttackSurfacePage() {
  const [summary, setSummary] = useState<AttackSurfaceSummary | null>(null);
  const [correlations, setCorrelations] = useState<SecurityCorrelation[] | null>(null);
  const [selected, setSelected] = useState<SecurityCorrelation | null>(null);
  const [assetDetail, setAssetDetail] = useState<AssetExposureSummary | null>(null);
  const [error, setError] = useState("");
  const [evaluating, setEvaluating] = useState(false);
  const [lifecycle, setLifecycle] = useState("");
  const [ruleId, setRuleId] = useState("");

  const load = useCallback(() => {
    setError("");
    getAttackSurfaceSummary()
      .then(setSummary)
      .catch(() => setError("UNAVAILABLE — failed to load attack surface overview."));
    listSecurityCorrelations({
      lifecycle: lifecycle || undefined,
      stable_rule_id: ruleId || undefined,
    })
      .then(setCorrelations)
      .catch(() => setError("UNAVAILABLE — failed to load correlations."));
  }, [lifecycle, ruleId]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleEvaluate() {
    setEvaluating(true);
    try {
      await evaluateCorrelations();
      load();
    } catch {
      setError("Failed to run correlation evaluation.");
    } finally {
      setEvaluating(false);
    }
  }

  async function openCorrelation(c: SecurityCorrelation) {
    setSelected(c);
    setAssetDetail(null);
    if (c.entity_ids.length > 0) {
      try {
        const detail = await getAssetExposureSummary(c.entity_ids[0]);
        setAssetDetail(detail);
      } catch {
        setAssetDetail(null);
      }
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Attack Surface</h1>
          <p className="mt-1 text-sm text-gray-400">
            Deterministic correlations across already-canonical security conditions —
            evidence-backed exposure concentration, never exploitability, compromise, or
            a magic risk score. Relationship context lives in the Security Graph, labeled
            as an Exposure Relationship Path, never an attack path.
          </p>
        </div>
        <button
          onClick={handleEvaluate}
          disabled={evaluating}
          className="rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 disabled:opacity-50"
        >
          {evaluating ? "Evaluating…" : "Run Evaluation"}
        </button>
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-3">
          <SummaryCard label="Assets w/ active conditions" count={summary.assets_with_active_conditions} />
          <SummaryCard
            label="Assets w/ multiple conditions"
            count={summary.assets_with_multiple_active_conditions}
          />
          <SummaryCard label="Active correlations" count={summary.active_correlations} />
        </div>
      ) : (
        <div className="mt-6 text-gray-400">Loading overview…</div>
      )}

      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={lifecycle}
          onChange={(e) => setLifecycle(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All lifecycle states</option>
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          value={ruleId}
          onChange={(e) => setRuleId(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All rules</option>
          <option value="PUBLIC_SENSITIVE_SERVICE_CONTEXT">Public sensitive service context</option>
          <option value="MULTIPLE_SECURITY_CONDITIONS_ON_ASSET">Multiple conditions on asset</option>
        </select>
      </div>

      {correlations === null ? (
        <div className="mt-6 text-gray-400">Loading correlations…</div>
      ) : correlations.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No correlations match the current filters. Run an evaluation if conditions exist.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {correlations.map((c) => (
            <button
              key={c.id}
              onClick={() => openCorrelation(c)}
              className="block w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-700"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-400">
                  {c.stable_rule_id}
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
                {c.entity_ids.length} entit{c.entity_ids.length === 1 ? "y" : "ies"} ·{" "}
                {c.condition_ids.length} source condition
                {c.condition_ids.length === 1 ? "" : "s"} · Last observed{" "}
                {new Date(c.last_observed_at).toLocaleString()}
              </div>
            </button>
          ))}
        </div>
      )}

      {selected ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="max-h-[85vh] w-full max-w-xl overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-start justify-between">
              <h2 className="text-lg font-semibold text-white">{selected.title}</h2>
              <button
                onClick={() => setSelected(null)}
                className="text-gray-500 hover:text-gray-300"
              >
                ✕
              </button>
            </div>
            <div className="mt-4 space-y-2 text-sm">
              <div>
                <span className="text-gray-500">Rule ID: </span>
                <span className="font-mono text-gray-300">
                  {selected.stable_rule_id} (v{selected.rule_version})
                </span>
              </div>
              <div>
                <span className="text-gray-500">Evidence state: </span>
                <span className="text-gray-300">{displayEnum(selected.evidence_state)}</span>
              </div>
              <div>
                <span className="text-gray-500">Summary: </span>
                <span className="text-gray-300">{selected.summary}</span>
              </div>
              <div>
                <span className="text-gray-500">Operator action: </span>
                <span className="text-gray-300">{selected.operator_action}</span>
              </div>
              <div>
                <span className="text-gray-500">Affected entities: </span>
                <span className="text-gray-300">{selected.entity_ids.join(", ")}</span>
              </div>
              <div>
                <span className="text-gray-500">Source conditions: </span>
                <span className="text-gray-300">{selected.condition_ids.join(", ")}</span>
              </div>
              <div>
                <span className="text-gray-500">First observed: </span>
                <span className="text-gray-300">
                  {new Date(selected.first_observed_at).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Last observed: </span>
                <span className="text-gray-300">
                  {new Date(selected.last_observed_at).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Lifecycle: </span>
                <span className="text-gray-300">
                  {selected.lifecycle === "resolved" ? "RESOLVED" : "ACTIVE"}
                </span>
              </div>

              {assetDetail ? (
                <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-3">
                  <div className="text-xs uppercase tracking-wide text-gray-500">
                    Asset Exposure — {assetDetail.asset_name}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                      {displayEnum(assetDetail.external_classification)}
                    </span>
                    <span className={`rounded px-2 py-0.5 text-xs ${severityBadge(assetDetail.highest_active_severity)}`}>
                      {displayEnum(assetDetail.highest_active_severity)}
                    </span>
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                      {assetDetail.active_condition_count} active conditions
                    </span>
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                      {assetDetail.sensitive_service_count} sensitive services
                    </span>
                  </div>
                </div>
              ) : null}
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setSelected(null)}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
