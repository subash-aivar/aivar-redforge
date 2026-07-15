"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listEntities,
  riskColor,
  baselineConfidenceLabel,
  type EntityRisk,
} from "@/lib/behavior";

export default function EntitiesPage() {
  const [entities, setEntities] = useState<EntityRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listEntities(200)
      .then(setEntities)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Entity Risk Matrix</h1>
          <p className="text-sm text-gray-400">
            Risk derived from active behavioral detections — no fabricated scores
          </p>
        </div>
        <Link href="/behavior" className="text-sm text-cyan-400 hover:text-cyan-300">← Overview</Link>
      </div>

      {loading ? (
        <div className="py-12 text-center text-gray-500">Loading entities…</div>
      ) : error ? (
        <div className="rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-400">{error}</div>
      ) : entities.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 py-12 text-center">
          <div className="text-2xl text-gray-700">◉</div>
          <div className="mt-2 text-sm text-gray-500">No entities in baseline yet</div>
          <div className="mt-1 text-xs text-gray-600">
            Entities appear after the behavior analysis worker processes telemetry windows
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800 px-5 py-3 grid grid-cols-5 gap-4 text-xs font-semibold uppercase tracking-wider text-gray-500">
            <div className="col-span-2">Entity</div>
            <div>Risk</div>
            <div>Active Det.</div>
            <div>Baseline</div>
          </div>
          <div className="divide-y divide-gray-800/50">
            {entities.map((e) => (
              <Link
                key={e.entity_id}
                href={`/behavior/entities/${encodeURIComponent(e.entity_id)}`}
                className="grid grid-cols-5 gap-4 items-center px-5 py-3 hover:bg-gray-800/50 transition-colors"
              >
                <div className="col-span-2 min-w-0">
                  <div className="font-mono text-sm text-gray-200 truncate">{e.entity_id}</div>
                  <div className="text-xs text-gray-600">{e.entity_type}</div>
                </div>
                <div>
                  <span className={`text-sm font-bold ${riskColor(e.risk_level)}`}>
                    {e.risk_level}
                  </span>
                </div>
                <div className="text-sm text-gray-300">
                  {e.active_detections > 0 ? (
                    <span className="font-medium text-orange-400">{e.active_detections}</span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </div>
                <div className="text-xs text-gray-500">
                  {baselineConfidenceLabel(e.baseline_confidence)}
                  <div className="text-gray-600">{e.window_count} windows</div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
