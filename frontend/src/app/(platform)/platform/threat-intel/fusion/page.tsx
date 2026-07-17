"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listFusedIndicators,
  listFusionWeights,
  updateFusionWeight,
  runFusion,
  confidenceColor,
  riskStateColor,
  lifecycleColor,
  INDICATOR_TYPES,
  INDICATOR_TYPE_LABELS,
  type FusedIndicator,
  type FusionRunResult,
} from "@/lib/fusion";

export default function FusionExplorerPage() {
  const [indicatorType, setIndicatorType] = useState<string>("technique");
  const [lifecycle, setLifecycle] = useState("");
  const [indicators, setIndicators] = useState<FusedIndicator[] | null>(null);
  const [loadError, setLoadError] = useState("");

  const [weights, setWeights] = useState<Record<string, number> | null>(null);
  const [weightsError, setWeightsError] = useState("");
  const [editingWeight, setEditingWeight] = useState<string | null>(null);
  const [weightDraft, setWeightDraft] = useState("");
  const [weightSaving, setWeightSaving] = useState(false);

  const [fusionResult, setFusionResult] = useState<FusionRunResult | null>(null);
  const [fusionRunning, setFusionRunning] = useState(false);
  const [fusionError, setFusionError] = useState("");

  function loadIndicators() {
    setIndicators(null);
    setLoadError("");
    listFusedIndicators({
      indicator_type: indicatorType,
      lifecycle: lifecycle || undefined,
      limit: 50,
    })
      .then(setIndicators)
      .catch(() => setLoadError("Failed to load fused indicators."));
  }

  useEffect(() => { loadIndicators(); }, [indicatorType, lifecycle]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    listFusionWeights()
      .then(setWeights)
      .catch(() => setWeightsError("Failed to load fusion weights."));
  }, []);

  async function saveWeight(source: string) {
    const w = parseFloat(weightDraft);
    if (isNaN(w) || w < 0 || w > 1) return;
    setWeightSaving(true);
    try {
      const updated = await updateFusionWeight(source, w);
      setWeights(updated);
      setEditingWeight(null);
    } catch {
      setWeightsError("Failed to update weight.");
    } finally {
      setWeightSaving(false);
    }
  }

  async function triggerFusion() {
    setFusionRunning(true);
    setFusionError("");
    setFusionResult(null);
    try {
      const result = await runFusion();
      setFusionResult(result);
      loadIndicators();
    } catch {
      setFusionError("Fusion run failed — check platform logs.");
    } finally {
      setFusionRunning(false);
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Fusion Explorer</h1>
          <p className="mt-1 text-sm text-gray-400">
            Browse fused indicators and administer source weights.
          </p>
        </div>
        <button
          onClick={triggerFusion}
          disabled={fusionRunning}
          className="rounded-lg bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
        >
          {fusionRunning ? "Running…" : "Run Fusion"}
        </button>
      </div>

      {fusionError && (
        <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-300">
          {fusionError}
        </div>
      )}
      {fusionResult && (
        <div className="mt-3 rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-2 text-sm text-emerald-300">
          Fusion complete — created {fusionResult.indicators_created}, updated{" "}
          {fusionResult.indicators_updated}, relationships {fusionResult.relationships_upserted}.
        </div>
      )}

      {/* Weights Panel */}
      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="text-sm font-medium text-gray-300">Source Weights</h2>
        {weightsError && <p className="mt-1 text-xs text-red-400">{weightsError}</p>}
        {!weights ? (
          <p className="mt-2 text-xs text-gray-600">Loading…</p>
        ) : Object.keys(weights).length === 0 ? (
          <p className="mt-2 text-xs text-gray-600">No weights configured.</p>
        ) : (
          <div className="mt-2 flex flex-wrap gap-3">
            {Object.entries(weights).map(([src, w]) => (
              <div key={src} className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5">
                <span className="text-xs text-gray-400">{src}</span>
                {editingWeight === src ? (
                  <div className="flex items-center gap-1">
                    <input
                      type="number"
                      step="0.05"
                      min="0"
                      max="1"
                      value={weightDraft}
                      onChange={(e) => setWeightDraft(e.target.value)}
                      className="w-16 rounded border border-gray-600 bg-gray-900 px-1.5 py-0.5 text-xs text-gray-200 focus:outline-none"
                    />
                    <button
                      onClick={() => saveWeight(src)}
                      disabled={weightSaving}
                      className="text-xs text-purple-400 hover:text-purple-300 disabled:opacity-50"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => setEditingWeight(null)}
                      className="text-xs text-gray-600 hover:text-gray-400"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <>
                    <span className="text-xs font-mono text-purple-300">{w.toFixed(2)}</span>
                    <button
                      onClick={() => { setEditingWeight(src); setWeightDraft(String(w)); }}
                      className="text-xs text-gray-600 hover:text-gray-400"
                    >
                      Edit
                    </button>
                  </>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Indicator List */}
      <div className="mt-6">
        <div className="flex flex-wrap gap-3">
          <select
            value={indicatorType}
            onChange={(e) => setIndicatorType(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-purple-600"
          >
            {INDICATOR_TYPES.map((t) => (
              <option key={t} value={t}>{INDICATOR_TYPE_LABELS[t] ?? t}</option>
            ))}
          </select>

          <div className="flex gap-1.5">
            {["", "active", "superseded", "expired", "revoked"].map((lc) => (
              <button
                key={lc || "all"}
                onClick={() => setLifecycle(lc)}
                className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
                  lifecycle === lc
                    ? "border-purple-700 bg-purple-950/60 text-purple-300"
                    : "border-gray-700 text-gray-500 hover:text-gray-300"
                }`}
              >
                {lc || "All"}
              </button>
            ))}
          </div>
        </div>

        {loadError ? (
          <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
            {loadError}
          </div>
        ) : !indicators ? (
          <div className="mt-6 text-sm text-gray-500">Loading…</div>
        ) : indicators.length === 0 ? (
          <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
            No fused indicators found for this filter.
          </div>
        ) : (
          <div className="mt-4 overflow-x-auto rounded-xl border border-gray-800">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500">
                  <th className="px-4 py-2 text-left">Name</th>
                  <th className="px-4 py-2 text-left">Lifecycle</th>
                  <th className="px-4 py-2 text-left">Confidence</th>
                  <th className="px-4 py-2 text-left">Risk</th>
                  <th className="px-4 py-2 text-left">Sources</th>
                  <th className="px-4 py-2 text-left">Winner</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((ind) => (
                  <tr key={ind.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-2">
                      <Link
                        href={`/platform/threat-intel/fusion/${ind.id}`}
                        className="text-gray-200 hover:text-purple-300"
                      >
                        {ind.display_name}
                      </Link>
                      <div className="font-mono text-xs text-gray-600">{ind.canonical_key}</div>
                    </td>
                    <td className="px-4 py-2">
                      <span className={`rounded border px-1.5 py-0.5 text-xs ${lifecycleColor(ind.lifecycle)}`}>
                        {ind.lifecycle}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      {ind.confidence ? (
                        <span className={`rounded border px-1.5 py-0.5 text-xs ${confidenceColor(ind.confidence)}`}>
                          {ind.confidence}
                        </span>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`rounded border px-1.5 py-0.5 text-xs ${riskStateColor(ind.risk_state)}`}>
                        {ind.risk_state}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-500">{ind.source_count}</td>
                    <td className="px-4 py-2 text-xs text-gray-500">{ind.winner_source_system ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
