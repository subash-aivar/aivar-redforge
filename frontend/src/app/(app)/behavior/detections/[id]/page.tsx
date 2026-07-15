"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  getDetection,
  closeDetection,
  severityColor,
  statusColor,
  detectionTypeLabel,
  type BehaviorDetection,
} from "@/lib/behavior";

export default function DetectionDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [detection, setDetection] = useState<BehaviorDetection | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [closing, setClosing] = useState(false);

  useEffect(() => {
    getDetection(id)
      .then(setDetection)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  const handleClose = async () => {
    if (!confirm("Close this detection?")) return;
    setClosing(true);
    try {
      await closeDetection(id, "Closed via UI");
      const updated = await getDetection(id);
      setDetection(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to close");
    } finally {
      setClosing(false);
    }
  };

  if (loading) return <div className="py-12 text-center text-gray-500">Loading detection…</div>;
  if (error) return <div className="rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-400">{error}</div>;
  if (!detection) return <div className="text-gray-500">Not found</div>;

  const evidence = detection.evidence as Record<string, unknown>;
  const signals = (evidence.matched_signals as unknown[]) ?? [];
  const missingEvidence = (evidence.missing_evidence as string[]) ?? [];
  const timeline = detection.timeline ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Link href="/behavior/detections" className="text-xs text-gray-500 hover:text-gray-400">
            ← Detections
          </Link>
          <h1 className="mt-1 text-xl font-bold text-white">
            {detectionTypeLabel(detection.detection_type)}
          </h1>
          <p className="text-sm text-gray-400 font-mono">{detection.entity_id}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityColor(detection.severity)}`}>
            {detection.severity}
          </span>
          <span className={`rounded-full border px-3 py-1 text-xs font-medium ${statusColor(detection.status)}`}>
            {detection.status}
          </span>
          {!["RESOLVED", "CLOSED"].includes(detection.status) && (
            <button
              onClick={handleClose}
              disabled={closing}
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-700 disabled:opacity-50"
            >
              {closing ? "Closing…" : "Close Detection"}
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Summary */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">Summary</div>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-gray-500">Entity</dt>
              <dd className="font-mono text-gray-200">{detection.entity_id}</dd>
            </div>
            {detection.secondary_entity_id && (
              <div className="flex justify-between">
                <dt className="text-gray-500">Secondary Entity</dt>
                <dd className="font-mono text-gray-200">{detection.secondary_entity_id}</dd>
              </div>
            )}
            <div className="flex justify-between">
              <dt className="text-gray-500">Type</dt>
              <dd className="text-gray-200">{detectionTypeLabel(detection.detection_type)}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Detection ID</dt>
              <dd className="font-mono text-xs text-gray-400">{detection.id}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Detected</dt>
              <dd className="text-gray-200">{new Date(detection.detected_at).toLocaleString()}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Last Seen</dt>
              <dd className="text-gray-200">{new Date(detection.last_seen_at).toLocaleString()}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Observations</dt>
              <dd className="text-white font-semibold">{detection.observation_count}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-500">Baseline confidence</dt>
              <dd className="text-gray-200">{String(evidence.baseline_confidence ?? "—")}</dd>
            </div>
          </dl>
        </div>

        {/* Why flagged */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Why Flagged
          </div>
          {evidence.explanation ? (
            <p className="text-sm text-gray-300 leading-relaxed">{String(evidence.explanation)}</p>
          ) : (
            <p className="text-sm text-gray-500">No explanation available</p>
          )}

          {signals.length > 0 && (
            <div className="mt-4 space-y-2">
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-600">
                Matched Signals
              </div>
              {(signals as Array<Record<string, unknown>>).map((sig, i) => (
                <div key={i} className="rounded-lg border border-gray-800 bg-gray-800/50 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-gray-300">{String(sig.name)}</span>
                    <span className="text-xs text-orange-400 font-bold">
                      {typeof sig.deviation === "number" ? `${sig.deviation.toFixed(1)}×` : "—"}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-gray-500">{String(sig.detail)}</div>
                </div>
              ))}
            </div>
          )}

          {missingEvidence.length > 0 && (
            <div className="mt-4">
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                Missing Evidence
              </div>
              <ul className="space-y-1">
                {missingEvidence.map((m, i) => (
                  <li key={i} className="text-xs text-gray-500">
                    <span className="text-gray-700">⚠ </span>{m}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Detection Timeline
          </div>
          <div className="space-y-3">
            {timeline.map((ev) => (
              <div key={ev.id} className="flex gap-3 text-sm">
                <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-cyan-500" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-300">{ev.event_type}</span>
                    <span className="text-xs text-gray-600">
                      {new Date(ev.created_at).toLocaleString()}
                    </span>
                  </div>
                  {ev.detail && (
                    <div className="mt-0.5 text-xs text-gray-500">{ev.detail}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Beaconing-specific evidence */}
      {detection.detection_type === "BEACONING_SUSPECTED" && evidence.median_interval_s != null && (
        <div className="rounded-xl border border-violet-800 bg-violet-950/20 p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-violet-500">
            Beaconing Analysis
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
            <div>
              <div className="text-xs text-gray-500">Sample Count</div>
              <div className="font-bold text-white">{String(evidence.sample_count ?? "—")}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Median Interval</div>
              <div className="font-bold text-white">
                {typeof evidence.median_interval_s === "number"
                  ? `${evidence.median_interval_s.toFixed(1)}s`
                  : "—"}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Jitter Coefficient</div>
              <div className="font-bold text-white">
                {typeof evidence.jitter_coefficient === "number"
                  ? evidence.jitter_coefficient.toFixed(3)
                  : "—"}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Destination</div>
              <div className="font-mono text-white">{String(evidence.dst_ip ?? "—")}</div>
            </div>
          </div>
          <div className="mt-3 rounded-lg border border-violet-800 bg-violet-950/40 px-3 py-2 text-xs text-violet-300">
            ⚠ Classification: BEACONING SUSPECTED — timing periodicity alone cannot confirm C2.
            False positives: monitoring agents, health checks, backup clients.
            Analyst review required.
          </div>
        </div>
      )}
    </div>
  );
}
