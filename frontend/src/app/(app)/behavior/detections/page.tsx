"use client";

import Link from "next/link";
import { useEffect, useState, useCallback } from "react";
import {
  listDetections,
  severityColor,
  severityDot,
  statusColor,
  detectionTypeLabel,
  type BehaviorDetection,
} from "@/lib/behavior";

export default function DetectionsPage() {
  const [detections, setDetections] = useState<BehaviorDetection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("");

  const load = useCallback(async () => {
    try {
      const d = await listDetections({ status: statusFilter || undefined, limit: 200 });
      setDetections(d);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Behavioral Detections</h1>
          <p className="text-sm text-gray-400">All evidence-backed behavioral anomalies</p>
        </div>
        <Link href="/behavior" className="text-sm text-cyan-400 hover:text-cyan-300">← Overview</Link>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {["", "DETECTED", "ACTIVE", "INVESTIGATING", "MONITORING", "RESOLVED", "CLOSED"].map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              statusFilter === s
                ? "border-cyan-500 bg-cyan-950 text-cyan-300"
                : "border-gray-700 bg-gray-900 text-gray-400 hover:bg-gray-800"
            }`}
          >
            {s || "All"}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="py-12 text-center text-gray-500">Loading…</div>
      ) : error ? (
        <div className="rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-400">{error}</div>
      ) : detections.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 py-12 text-center">
          <div className="text-2xl text-gray-700">◎</div>
          <div className="mt-2 text-sm text-gray-500">No detections match the current filter</div>
        </div>
      ) : (
        <div className="rounded-xl border border-gray-800 bg-gray-900">
          <div className="divide-y divide-gray-800/50">
            {detections.map((d) => (
              <Link
                key={d.id}
                href={`/behavior/detections/${d.id}`}
                className="flex items-start gap-3 px-5 py-4 hover:bg-gray-800/50 transition-colors"
              >
                <div className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${severityDot(d.severity)}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm text-cyan-300">{d.entity_id}</span>
                    {d.secondary_entity_id && (
                      <span className="text-xs text-gray-500">→ {d.secondary_entity_id}</span>
                    )}
                    <span className="rounded border border-gray-700 bg-gray-800 px-2 py-0.5 text-xs text-gray-300">
                      {detectionTypeLabel(d.detection_type)}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-gray-500 line-clamp-2">
                    {(d.evidence as Record<string, string>)?.explanation ?? "No explanation available"}
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-gray-600">
                    <span>Detected: {new Date(d.detected_at).toLocaleString()}</span>
                    <span>Last: {new Date(d.last_seen_at).toLocaleString()}</span>
                    <span>Observations: {d.observation_count}</span>
                  </div>
                </div>
                <div className="shrink-0 flex flex-col items-end gap-1">
                  <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${severityColor(d.severity)}`}>
                    {d.severity}
                  </span>
                  <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(d.status)}`}>
                    {d.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
