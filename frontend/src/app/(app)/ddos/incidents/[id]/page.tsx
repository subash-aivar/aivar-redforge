"use client";

import Link from "next/link";
import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  getIncident,
  getIncidentTimeline,
  listIncidentRecommendations,
  closeIncident,
  approveRecommendation,
  rejectRecommendation,
  severityColor,
  statusColor,
  formatBps,
  formatPps,
  type DDoSIncident,
  type IncidentTimelineEvent,
  type MitigationRecommendation,
} from "@/lib/ddos";

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`rounded-full border px-3 py-1 text-sm font-bold ${severityColor(severity)}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded-full border px-3 py-1 text-sm font-bold ${statusColor(status)}`}>
      {status}
    </span>
  );
}

function EvidenceSection({ evidence }: { evidence: Record<string, unknown> }) {
  const signals = (evidence?.matched_signals as Array<Record<string, unknown>>) ?? [];
  const missing = (evidence?.missing_evidence as string[]) ?? [];
  const baseline = evidence?.baseline as Record<string, unknown> | undefined;
  const metrics = evidence?.metrics as Record<string, unknown> | undefined;

  return (
    <div className="space-y-4">
      {signals.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Matched Signals</h4>
          <div className="space-y-2">
            {signals.map((s, i) => (
              <div key={i} className="rounded-lg border border-gray-800 bg-gray-900 p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-semibold text-white">{String(s.name)}</span>
                  <span className="rounded bg-orange-950 px-2 py-0.5 text-xs font-bold text-orange-300">
                    {typeof s.deviation_multiplier === "number" ? `${s.deviation_multiplier.toFixed(1)}x` : "—"}
                  </span>
                </div>
                <div className="mt-1 text-xs text-gray-400">{String(s.detail ?? "")}</div>
                <div className="mt-1 flex gap-4 text-xs text-gray-500">
                  <span>baseline: <span className="font-mono text-gray-400">{String(s.baseline_source)}</span></span>
                  <span>threshold: <span className="font-mono text-gray-400">{typeof s.threshold === "number" ? s.threshold.toLocaleString() : "—"}</span></span>
                  <span>observed: <span className="font-mono text-gray-400">{typeof s.observed === "number" ? s.observed.toLocaleString() : "—"}</span></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {missing.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Missing Evidence</h4>
          <div className="space-y-1">
            {missing.map((m, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-gray-500">
                <span className="mt-0.5 text-yellow-600">⚠</span>
                <span>{m}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {baseline && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Baseline</h4>
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs text-gray-400">Confidence:</span>
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs font-mono text-gray-300">
                {String(baseline.confidence)}
              </span>
              <span className="text-xs text-gray-500">({String(baseline.window_count)} windows)</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {baseline.p75_bytes_per_second != null && (
                <div><span className="text-gray-500">p75 BPS:</span> <span className="font-mono text-gray-300">{formatBps(Number(baseline.p75_bytes_per_second))}</span></div>
              )}
              {baseline.p75_packets_per_second != null && (
                <div><span className="text-gray-500">p75 PPS:</span> <span className="font-mono text-gray-300">{formatPps(Number(baseline.p75_packets_per_second))}</span></div>
              )}
              {baseline.p75_unique_src_ips != null && (
                <div><span className="text-gray-500">p75 Sources:</span> <span className="font-mono text-gray-300">{Number(baseline.p75_unique_src_ips).toLocaleString()}</span></div>
              )}
            </div>
          </div>
        </div>
      )}

      {metrics && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Window Metrics</h4>
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div><span className="text-gray-500">Events:</span> <span className="font-mono text-gray-300">{String(metrics.event_count)}</span></div>
              <div><span className="text-gray-500">Unique Sources:</span> <span className="font-mono text-gray-300">{String(metrics.unique_src_ips)}</span></div>
              {metrics.bytes_per_second != null && (
                <div><span className="text-gray-500">BPS:</span> <span className="font-mono text-gray-300">{formatBps(Number(metrics.bytes_per_second))}</span></div>
              )}
              {metrics.packets_per_second != null && (
                <div><span className="text-gray-500">PPS:</span> <span className="font-mono text-gray-300">{formatPps(Number(metrics.packets_per_second))}</span></div>
              )}
            </div>
            {metrics.window_start_ts != null && (
              <div className="mt-2 text-xs text-gray-500">
                Window: {String(metrics.window_start_ts)} → {String(metrics.window_end_ts)}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = params.id as string;

  const [incident, setIncident] = useState<DDoSIncident | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimelineEvent[]>([]);
  const [recs, setRecs] = useState<MitigationRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const load = useCallback(async () => {
    try {
      const [inc, tl, r] = await Promise.all([
        getIncident(incidentId),
        getIncidentTimeline(incidentId),
        listIncidentRecommendations(incidentId),
      ]);
      setIncident(inc);
      setTimeline(tl);
      setRecs(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incident");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 15_000);
    return () => clearInterval(iv);
  }, [load]);

  const handleClose = async () => {
    try {
      await closeIncident(incidentId);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to close incident");
    }
  };

  const handleApprove = async (recId: string) => {
    try {
      setActionError(null);
      await approveRecommendation(recId);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to approve recommendation");
    }
  };

  const handleReject = async (recId: string) => {
    try {
      setActionError(null);
      await rejectRecommendation(recId, rejectReason || "Rejected by operator");
      setRejectReason("");
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to reject recommendation");
    }
  };

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-gray-400">Loading incident…</div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="m-6 rounded-xl border border-red-800 bg-red-950 p-6 text-red-300">
        {error ?? "Incident not found"}
      </div>
    );
  }

  const isOpen = !["RESOLVED", "CLOSED"].includes(incident.status);
  const durationMs = (incident.resolved_at ? new Date(incident.resolved_at) : new Date()).getTime() - new Date(incident.first_detected_at).getTime();
  const durationMin = Math.floor(durationMs / 60_000);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-500 mb-1">
            <Link href="/ddos" className="hover:text-gray-300">DDoS</Link>
            <span>/</span>
            <Link href="/ddos/incidents" className="hover:text-gray-300">Incidents</Link>
            <span>/</span>
            <span className="font-mono text-gray-400">{incidentId.slice(-8).toUpperCase()}</span>
          </div>
          <h1 className="text-2xl font-bold text-white">{incident.resource_name}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <StatusBadge status={incident.status} />
            <SeverityBadge severity={incident.severity} />
            <span className="text-sm text-gray-400">{incident.classification?.replace(/_/g, " ")}</span>
          </div>
        </div>
        {isOpen && (
          <button
            onClick={handleClose}
            className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
          >
            Close Incident
          </button>
        )}
      </div>

      {actionError && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-3 text-sm text-red-300">{actionError}</div>
      )}

      {/* Metrics grid */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Peak BPS</div>
          <div className="mt-1 text-xl font-bold text-white font-mono">{formatBps(incident.peak_bytes_per_second)}</div>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Peak PPS</div>
          <div className="mt-1 text-xl font-bold text-white font-mono">{formatPps(incident.peak_packets_per_second)}</div>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Peak Sources</div>
          <div className="mt-1 text-xl font-bold text-white font-mono">
            {incident.peak_unique_src_ips?.toLocaleString() ?? "—"}
          </div>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Max Deviation</div>
          <div className={`mt-1 text-xl font-bold font-mono ${
            (incident.peak_deviation_multiplier ?? 0) >= 20 ? "text-red-400" :
            (incident.peak_deviation_multiplier ?? 0) >= 10 ? "text-orange-400" :
            (incident.peak_deviation_multiplier ?? 0) >= 5 ? "text-yellow-400" : "text-blue-400"
          }`}>
            {incident.peak_deviation_multiplier != null ? `${incident.peak_deviation_multiplier.toFixed(1)}x` : "—"}
          </div>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Evidence */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-5">
          <h2 className="mb-4 text-base font-semibold text-white">Detection Evidence</h2>
          <EvidenceSection evidence={incident.latest_evidence} />
        </div>

        {/* Timeline */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-5">
          <h2 className="mb-4 text-base font-semibold text-white">Incident Timeline</h2>
          <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
            {timeline.length === 0 && (
              <div className="text-sm text-gray-500">No timeline events yet</div>
            )}
            {timeline.map((ev) => (
              <div key={ev.id} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <div className={`h-2 w-2 rounded-full flex-shrink-0 mt-1 ${
                    ev.event_type.includes("opened") || ev.event_type.includes("escalated")
                      ? "bg-red-500"
                      : ev.event_type.includes("resolved") || ev.event_type.includes("closed")
                      ? "bg-emerald-500"
                      : "bg-blue-500"
                  }`} />
                  <div className="mt-1 w-px flex-1 bg-gray-800" />
                </div>
                <div className="pb-3 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-blue-400">{ev.event_type}</span>
                    <span className="text-xs text-gray-600">{new Date(ev.occurred_at).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5">{ev.description}</div>
                  {ev.actor_id && (
                    <div className="text-xs text-gray-600 mt-0.5">by {ev.actor_id}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Mitigation Recommendations */}
      <div className="rounded-xl border border-gray-800 bg-gray-950 p-5">
        <h2 className="mb-4 text-base font-semibold text-white">Mitigation Recommendations</h2>
        <div className="mb-3 text-xs text-gray-500">
          All mitigation actions require explicit operator approval (RECOMMEND_ONLY mode).
          No automated execution occurs.
        </div>
        {recs.length === 0 ? (
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm text-gray-500">
            No mitigation recommendations yet
          </div>
        ) : (
          <div className="space-y-3">
            {recs.map(rec => (
              <div key={rec.id} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-gray-400">{rec.recommendation_type}</span>
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${
                        rec.approval_status === "APPROVED" ? "border-emerald-800 bg-emerald-950 text-emerald-400" :
                        rec.approval_status === "REJECTED" ? "border-gray-700 bg-gray-800 text-gray-500" :
                        "border-orange-800 bg-orange-950 text-orange-400"
                      }`}>
                        {rec.approval_status}
                      </span>
                    </div>
                    <div className="mt-1 text-sm text-gray-200">{rec.description}</div>
                    {rec.approved_by && (
                      <div className="mt-1 text-xs text-emerald-600">Approved by {rec.approved_by}</div>
                    )}
                    {rec.rejection_reason && (
                      <div className="mt-1 text-xs text-gray-500">Rejected: {rec.rejection_reason}</div>
                    )}
                    <div className="mt-2 text-xs text-gray-500">
                      Execution: {rec.execution_status} · Provider: {rec.provider_type ?? "NOT CONFIGURED"}
                    </div>
                  </div>
                  {rec.approval_status === "PENDING" && (
                    <div className="flex flex-col gap-2 flex-shrink-0">
                      <button
                        onClick={() => handleApprove(rec.id)}
                        className="rounded border border-emerald-800 bg-emerald-950 px-3 py-1 text-xs font-semibold text-emerald-300 hover:bg-emerald-900"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => handleReject(rec.id)}
                        className="rounded border border-gray-700 bg-gray-800 px-3 py-1 text-xs font-semibold text-gray-400 hover:bg-gray-700"
                      >
                        Reject
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Incident Metadata */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h3 className="mb-3 text-sm font-semibold text-gray-300">Incident Details</h3>
        <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
          <div>
            <div className="text-gray-500">Incident ID</div>
            <div className="font-mono text-gray-300">{incidentId}</div>
          </div>
          <div>
            <div className="text-gray-500">First Detected</div>
            <div className="text-gray-300">{new Date(incident.first_detected_at).toLocaleString()}</div>
          </div>
          <div>
            <div className="text-gray-500">Duration</div>
            <div className="text-gray-300">{durationMin}m</div>
          </div>
          <div>
            <div className="text-gray-500">Quiet Windows</div>
            <div className="text-gray-300">{incident.consecutive_quiet_windows}</div>
          </div>
          {incident.resolved_at && (
            <div>
              <div className="text-gray-500">Resolved At</div>
              <div className="text-emerald-400">{new Date(incident.resolved_at).toLocaleString()}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
