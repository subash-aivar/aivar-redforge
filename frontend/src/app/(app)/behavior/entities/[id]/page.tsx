"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  getEntityBehavior,
  severityColor,
  statusColor,
  detectionTypeLabel,
  formatBytes,
  baselineConfidenceLabel,
  type EntityBehavior,
} from "@/lib/behavior";

export default function EntityBehaviorPage() {
  const params = useParams();
  const entityId = decodeURIComponent(params.id as string);
  const [entity, setEntity] = useState<EntityBehavior | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEntityBehavior(entityId)
      .then(setEntity)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [entityId]);

  if (loading) return <div className="py-12 text-center text-gray-500">Loading entity profile…</div>;
  if (error) return <div className="rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-400">{error}</div>;
  if (!entity) return <div className="text-gray-500">Entity not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Link href="/behavior/entities" className="text-xs text-gray-500 hover:text-gray-400">
            ← Entity Risk
          </Link>
          <h1 className="mt-1 font-mono text-xl font-bold text-white">{entity.entity_id}</h1>
          <p className="text-sm text-gray-400">{entity.entity_type}</p>
        </div>
      </div>

      {/* Baseline summary */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          { label: "Baseline Confidence", value: baselineConfidenceLabel(entity.baseline_confidence) },
          { label: "Observation Windows", value: entity.window_count },
          { label: "Seen Destinations", value: entity.seen_dst_ip_count },
          { label: "Active Detections", value: entity.detections.filter(d => !["RESOLVED","CLOSED"].includes(d.status)).length },
        ].map((m) => (
          <div key={m.label} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <div className="text-2xl font-bold text-white">{m.value}</div>
            <div className="mt-1 text-xs text-gray-400">{m.label}</div>
          </div>
        ))}
      </div>

      {/* Baseline stats */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
          Behavioral Baseline (p75 of {entity.window_count} windows)
        </div>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <div className="text-xs text-gray-500">Unique Destinations (p75)</div>
            <div className="font-bold text-white">
              {entity.p75_unique_dst_ips.toFixed(1)}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Bytes Out (p75)</div>
            <div className="font-bold text-white">
              {entity.p75_bytes_out != null ? formatBytes(entity.p75_bytes_out) : "—"}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Event Count (p75)</div>
            <div className="font-bold text-white">
              {entity.p75_event_count.toFixed(1)}
            </div>
          </div>
        </div>
      </div>

      {/* Recent observations */}
      {entity.recent_observations.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Recent Observation Windows
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500">
                  <th className="pb-2 text-left">Window Start</th>
                  <th className="pb-2 text-right">Events</th>
                  <th className="pb-2 text-right">Unique Dsts</th>
                  <th className="pb-2 text-right">Unique Ports</th>
                  <th className="pb-2 text-right">Bytes Out</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {entity.recent_observations.map((obs) => (
                  <tr key={obs.window_start_ts}>
                    <td className="py-2 text-gray-300 text-xs">
                      {new Date(obs.window_start_ts).toLocaleString()}
                    </td>
                    <td className="py-2 text-right text-gray-200">{obs.event_count}</td>
                    <td className="py-2 text-right text-gray-200">{obs.unique_dst_ips}</td>
                    <td className="py-2 text-right text-gray-200">{obs.unique_dst_ports}</td>
                    <td className="py-2 text-right text-gray-200">{formatBytes(obs.total_bytes_out)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Active detections */}
      {entity.detections.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Behavioral Detections
          </div>
          <div className="space-y-3">
            {entity.detections.map((d) => (
              <Link
                key={d.id}
                href={`/behavior/detections/${d.id}`}
                className="flex items-start justify-between gap-3 rounded-lg border border-gray-800 bg-gray-800/50 p-3 hover:bg-gray-800"
              >
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-200">
                    {detectionTypeLabel(d.detection_type)}
                  </div>
                  <div className="mt-0.5 text-xs text-gray-500 line-clamp-1">
                    {(d.evidence as Record<string, string>)?.explanation ?? "—"}
                  </div>
                  <div className="mt-1 text-xs text-gray-600">
                    {new Date(d.detected_at).toLocaleString()} · {d.observation_count} obs.
                  </div>
                </div>
                <div className="shrink-0 flex flex-col items-end gap-1">
                  <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${severityColor(d.severity)}`}>
                    {d.severity}
                  </span>
                  <span className={`rounded-full border px-2 py-0.5 text-xs ${statusColor(d.status)}`}>
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
