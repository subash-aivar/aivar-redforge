"use client";

import Link from "next/link";
import { useState, useCallback } from "react";
import { useLivePoll } from "@/lib/useLivePoll";
import { RealtimeTimestamp } from "@/components/platform/LiveIndicators";
import { PageHeader } from "@/components/cc";
import {
  getBehaviorPosture,
  listDetections,
  listEntities,
  severityColor,
  severityDot,
  statusColor,
  riskColor,
  detectionTypeLabel,
  formatBytes,
  baselineConfidenceLabel,
  type BehaviorPosture,
  type BehaviorDetection,
  type EntityRisk,
} from "@/lib/behavior";

// ── Sub-components ────────────────────────────────────────────────────────────

function MetricTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className={`text-3xl font-bold ${accent ?? "text-white"}`}>{value}</div>
      <div className="mt-1 text-sm font-semibold text-gray-300">{label}</div>
      {sub && <div className="mt-0.5 text-xs text-gray-500">{sub}</div>}
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

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(status)}`}>
      {status}
    </span>
  );
}

function DetectionTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    BEACONING_SUSPECTED: "border-violet-500 bg-violet-950 text-violet-300",
    HIGH_FAN_OUT: "border-orange-500 bg-orange-950 text-orange-300",
    PORT_SCAN_SUSPECTED: "border-red-500 bg-red-950 text-red-300",
    NEW_DESTINATION: "border-cyan-500 bg-cyan-950 text-cyan-300",
    RARE_DESTINATION: "border-teal-500 bg-teal-950 text-teal-300",
    ABNORMAL_OUTBOUND_TRANSFER: "border-yellow-500 bg-yellow-950 text-yellow-300",
    UNUSUAL_EAST_WEST: "border-pink-500 bg-pink-950 text-pink-300",
    UNUSUAL_SERVICE_ACCESS: "border-indigo-500 bg-indigo-950 text-indigo-300",
  };
  return (
    <span className={`rounded border px-2 py-0.5 text-xs font-medium ${colors[type] ?? "border-gray-600 bg-gray-900 text-gray-400"}`}>
      {detectionTypeLabel(type)}
    </span>
  );
}

function LivePulse() {
  return (
    <span className="relative flex h-2 w-2">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
      <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BehaviorOverviewPage() {
  const [posture, setPosture] = useState<BehaviorPosture | null>(null);
  const [detections, setDetections] = useState<BehaviorDetection[]>([]);
  const [entities, setEntities] = useState<EntityRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const [p, d, e] = await Promise.all([
        getBehaviorPosture(),
        listDetections({ limit: 50 }),
        listEntities(50),
      ]);
      setPosture(p);
      setDetections(d);
      setEntities(e);
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load behavioral data");
    } finally {
      setLoading(false);
    }
  }, []);

  useLivePoll(load, 30_000);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
          <div className="text-sm text-gray-400">Loading behavioral intelligence…</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-800 bg-red-950/30 p-6">
        <div className="font-semibold text-red-400">Failed to load behavioral data</div>
        <div className="mt-1 text-sm text-gray-400">{error}</div>
        <button onClick={load} className="mt-3 rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">
          Retry
        </button>
      </div>
    );
  }

  const criticalCount = posture?.detections_by_severity?.["CRITICAL"] ?? 0;
  const highCount = posture?.detections_by_severity?.["HIGH"] ?? 0;
  const mediumCount = posture?.detections_by_severity?.["MEDIUM"] ?? 0;
  const activeDetections = posture?.active_detections ?? 0;

  const beaconingCount = detections.filter(d => d.detection_type === "BEACONING_SUSPECTED").length;
  const fanOutCount = detections.filter(d => d.detection_type === "HIGH_FAN_OUT").length;
  const scanCount = detections.filter(d => d.detection_type === "PORT_SCAN_SUSPECTED").length;
  const eastWestCount = detections.filter(d => d.detection_type === "UNUSUAL_EAST_WEST").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="NDR Operations Center"
        subtitle="Behavioral anomaly detection — evidence-driven, no fabricated signals"
        actions={
          <div className="text-right">
            <div className="flex items-center justify-end gap-2">
              <div className="flex items-center gap-1.5 rounded-full border border-emerald-700 bg-emerald-950 px-2.5 py-1 text-xs font-medium text-emerald-400">
                <LivePulse />
                LIVE
              </div>
              {lastRefresh && (
                <div className="text-xs text-gray-600">
                  <RealtimeTimestamp iso={lastRefresh.toISOString()} prefix="Updated " />
                </div>
              )}
            </div>
            <div className="mt-1 flex gap-2">
              <Link
                href="/behavior/detections"
                className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-800"
              >
                All Detections
              </Link>
              <Link
                href="/behavior/entities"
                className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-800"
              >
                Entity Risk
              </Link>
              <Link
                href="/behavior/network"
                className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-800"
              >
                Network Graph
              </Link>
            </div>
          </div>
        }
      />

      {/* Global Posture Header */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
        <MetricTile
          label="Active Detections"
          value={activeDetections}
          sub="behavioral anomalies"
          accent={activeDetections > 0 ? "text-orange-400" : "text-white"}
        />
        <MetricTile
          label="Critical / High"
          value={criticalCount + highCount}
          sub="requiring investigation"
          accent={criticalCount > 0 ? "text-red-400" : highCount > 0 ? "text-orange-400" : "text-white"}
        />
        <MetricTile
          label="Monitored Entities"
          value={posture?.monitored_entities ?? 0}
          sub="source IPs with baselines"
        />
        <MetricTile
          label="Established Baselines"
          value={posture?.established_baselines ?? 0}
          sub="adaptive baselines"
          accent="text-emerald-400"
        />
        <MetricTile
          label="Beaconing Suspected"
          value={beaconingCount}
          sub="periodic comm patterns"
          accent={beaconingCount > 0 ? "text-violet-400" : "text-white"}
        />
        <MetricTile
          label="East-West Unusual"
          value={eastWestCount}
          sub="new internal pairs"
          accent={eastWestCount > 0 ? "text-pink-400" : "text-white"}
        />
      </div>

      {/* Detection type breakdown */}
      {Object.keys(posture?.detections_by_type ?? {}).length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Active Detection Types
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(posture?.detections_by_type ?? {}).map(([type, count]) => (
              <div key={type} className="flex items-center gap-1.5 rounded-full border border-gray-700 bg-gray-800 px-3 py-1">
                <DetectionTypeBadge type={type} />
                <span className="text-sm font-bold text-white">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Live Behavior Radar */}
        <div className="col-span-2 rounded-xl border border-gray-800 bg-gray-900">
          <div className="flex items-center justify-between border-b border-gray-800 px-5 py-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-orange-500" />
              <span className="text-sm font-semibold text-gray-200">Live Behavior Radar</span>
            </div>
            <Link href="/behavior/detections" className="text-xs text-cyan-400 hover:text-cyan-300">
              View all →
            </Link>
          </div>
          <div className="divide-y divide-gray-800/50">
            {detections.length === 0 ? (
              <div className="px-5 py-8 text-center">
                <div className="text-2xl text-gray-700">◎</div>
                <div className="mt-2 text-sm text-gray-500">
                  No active behavioral detections
                </div>
                <div className="mt-1 text-xs text-gray-600">
                  {posture?.monitored_entities === 0
                    ? "No entities in baseline yet — detections fire after first telemetry windows"
                    : "Behavioral patterns within established baselines"}
                </div>
              </div>
            ) : (
              detections.slice(0, 15).map((d) => (
                <Link
                  key={d.id}
                  href={`/behavior/detections/${d.id}`}
                  className="flex items-start gap-3 px-5 py-3.5 hover:bg-gray-800/50 transition-colors"
                >
                  <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${severityDot(d.severity)}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm text-cyan-300">{d.entity_id}</span>
                      {d.secondary_entity_id && (
                        <>
                          <span className="text-gray-600">→</span>
                          <span className="font-mono text-sm text-gray-400">{d.secondary_entity_id}</span>
                        </>
                      )}
                      <DetectionTypeBadge type={d.detection_type} />
                    </div>
                    <div className="mt-1 text-xs text-gray-500 line-clamp-1">
                      {(d.evidence as Record<string, string>)?.explanation ?? "—"}
                    </div>
                    <div className="mt-1 flex items-center gap-3 text-xs text-gray-600">
                      <span>{new Date(d.detected_at).toLocaleString()}</span>
                      <span>obs: {d.observation_count}</span>
                    </div>
                  </div>
                  <div className="shrink-0 flex flex-col items-end gap-1">
                    <SeverityBadge severity={d.severity} />
                    <StatusBadge status={d.status} />
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Entity Risk Matrix */}
        <div className="rounded-xl border border-gray-800 bg-gray-900">
          <div className="flex items-center justify-between border-b border-gray-800 px-5 py-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-cyan-500" />
              <span className="text-sm font-semibold text-gray-200">Entity Risk</span>
            </div>
            <Link href="/behavior/entities" className="text-xs text-cyan-400 hover:text-cyan-300">
              All →
            </Link>
          </div>
          <div className="divide-y divide-gray-800/50">
            {entities.length === 0 ? (
              <div className="px-5 py-8 text-center">
                <div className="text-sm text-gray-500">No entities monitored yet</div>
                <div className="mt-1 text-xs text-gray-600">
                  Entities appear after first telemetry windows are processed
                </div>
              </div>
            ) : (
              entities.slice(0, 10).map((e) => (
                <Link
                  key={e.entity_id}
                  href={`/behavior/entities/${encodeURIComponent(e.entity_id)}`}
                  className="flex items-center justify-between gap-3 px-5 py-3 hover:bg-gray-800/50 transition-colors"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-sm text-gray-200 truncate">{e.entity_id}</div>
                    <div className="mt-0.5 text-xs text-gray-600">
                      {baselineConfidenceLabel(e.baseline_confidence)} · {e.window_count} windows
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <div className={`text-sm font-bold ${riskColor(e.risk_level)}`}>{e.risk_level}</div>
                    {e.active_detections > 0 && (
                      <div className="text-xs text-gray-500">{e.active_detections} det.</div>
                    )}
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Unsupported detections notice */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/50 px-5 py-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
          Canonical Evidence Basis
        </div>
        <div className="grid grid-cols-1 gap-3 text-xs text-gray-500 md:grid-cols-2">
          <div>
            <span className="font-medium text-emerald-600">Supported:</span>{" "}
            New/rare destinations, fan-out, port scanning, beaconing, outbound transfer,
            east-west pairs, unusual service access — all from canonical telemetry_events.
          </div>
          <div>
            <span className="font-medium text-gray-600">Honestly unsupported:</span>{" "}
            User authentication anomalies, impossible travel, failed-connection ratio,
            lateral movement confirmed — no canonical evidence available.
          </div>
        </div>
      </div>
    </div>
  );
}
