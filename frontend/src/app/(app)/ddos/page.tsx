"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  getDDoSPosture,
  listActiveIncidents,
  listPendingRecommendations,
  severityColor,
  statusColor,
  formatBps,
  type DDoSPosture,
  type DDoSIncident,
  type MitigationRecommendation,
} from "@/lib/ddos";

function MetricTile({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className="text-3xl font-bold text-white">{value}</div>
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
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${statusColor(status)}`}>
      {status}
    </span>
  );
}

export default function DDoSOverviewPage() {
  const [posture, setPosture] = useState<DDoSPosture | null>(null);
  const [incidents, setIncidents] = useState<DDoSIncident[]>([]);
  const [pending, setPending] = useState<MitigationRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [p, inc, recs] = await Promise.all([
          getDDoSPosture(),
          listActiveIncidents(),
          listPendingRecommendations(),
        ]);
        setPosture(p);
        setIncidents(inc);
        setPending(recs);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load DDoS data");
      } finally {
        setLoading(false);
      }
    };
    load();
    const iv = setInterval(load, 30_000);
    return () => clearInterval(iv);
  }, []);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-gray-400">Loading DDoS posture…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="m-6 rounded-xl border border-red-800 bg-red-950 p-6 text-red-300">
        {error}
      </div>
    );
  }

  const critCount = posture?.active_incident_severity_counts?.["CRITICAL"] ?? 0;
  const highCount = posture?.active_incident_severity_counts?.["HIGH"] ?? 0;

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">DDoS Defense Center</h1>
          <p className="mt-1 text-sm text-gray-400">
            Evidence-based detection from telemetry aggregation · Operator-gated mitigation
          </p>
        </div>
        <div className="flex gap-3">
          <Link
            href="/ddos/protected-resources"
            className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-gray-700"
          >
            Protected Resources
          </Link>
          <Link
            href="/ddos/mitigation"
            className={`rounded-lg border px-4 py-2 text-sm font-medium ${
              pending.length > 0
                ? "border-orange-700 bg-orange-950 text-orange-300 hover:bg-orange-900"
                : "border-gray-700 bg-gray-800 text-gray-200 hover:bg-gray-700"
            }`}
          >
            Mitigation Center {pending.length > 0 && `(${pending.length} pending)`}
          </Link>
        </div>
      </div>

      {/* Active alert banner */}
      {(critCount > 0 || highCount > 0) && (
        <div className="flex items-center gap-3 rounded-xl border border-red-800 bg-red-950 px-5 py-4">
          <span className="text-2xl">⚡</span>
          <div>
            <div className="font-semibold text-red-300">
              Active DDoS attack in progress
            </div>
            <div className="text-sm text-red-400">
              {critCount > 0 && `${critCount} CRITICAL `}
              {highCount > 0 && `${highCount} HIGH `}
              incident{(critCount + highCount) !== 1 ? "s" : ""} detected
            </div>
          </div>
          <Link href="/ddos/incidents" className="ml-auto rounded-lg border border-red-700 px-4 py-2 text-sm font-semibold text-red-300 hover:bg-red-900">
            Investigate →
          </Link>
        </div>
      )}

      {/* Metrics */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <MetricTile
          label="Protected Resources"
          value={posture?.protected_resource_count ?? 0}
          sub="with enabled policies"
        />
        <MetricTile
          label="Active Incidents"
          value={posture?.active_incident_count ?? 0}
          sub={critCount > 0 ? `${critCount} critical` : "none critical"}
        />
        <MetricTile
          label="Pending Mitigations"
          value={posture?.pending_recommendation_count ?? 0}
          sub="awaiting operator approval"
        />
        <MetricTile
          label="Severity Distribution"
          value={Object.entries(posture?.active_incident_severity_counts ?? {})
            .filter(([, v]) => v > 0)
            .map(([k, v]) => `${v} ${k}`)
            .join(" · ") || "—"}
          sub="active incidents"
        />
      </div>

      {/* Active Incidents Table */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Active Incidents</h2>
          <Link href="/ddos/incidents" className="text-sm text-blue-400 hover:underline">
            View all →
          </Link>
        </div>
        {incidents.length === 0 ? (
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-500">
            No active DDoS incidents — all resources are within normal traffic bounds
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800 bg-gray-900 text-gray-400">
                <tr>
                  <th className="px-4 py-3 text-left font-medium">Resource</th>
                  <th className="px-4 py-3 text-left font-medium">Status</th>
                  <th className="px-4 py-3 text-left font-medium">Severity</th>
                  <th className="px-4 py-3 text-left font-medium">Classification</th>
                  <th className="px-4 py-3 text-left font-medium">Peak BPS</th>
                  <th className="px-4 py-3 text-left font-medium">Detected</th>
                  <th className="px-4 py-3 text-left font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-gray-900">
                    <td className="px-4 py-3 font-medium text-white">{inc.resource_name}</td>
                    <td className="px-4 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3 text-gray-300">{inc.classification?.replace(/_/g, " ")}</td>
                    <td className="px-4 py-3 font-mono text-gray-300">{formatBps(inc.peak_bytes_per_second)}</td>
                    <td className="px-4 py-3 text-gray-400">{new Date(inc.first_detected_at).toLocaleTimeString()}</td>
                    <td className="px-4 py-3">
                      <Link
                        href={`/ddos/incidents/${inc.id}`}
                        className="text-blue-400 hover:underline"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detection constraints notice */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h3 className="mb-2 text-sm font-semibold text-gray-300">Detection Evidence Basis</h3>
        <p className="text-xs text-gray-500 leading-relaxed">
          Detection is derived from real-time aggregation of <code className="text-gray-400">telemetry_events</code> — bytes, packets, flows, protocol distribution, and Suricata alert signatures.
          The following signals are <strong className="text-gray-400">not available</strong> in the current schema: TCP flag counters (not stored),
          L7 request rates (no HTTP field), true SYN/ACK ratios (no TCP state machine). Every active detection
          displays its evidence signals. &quot;SUSPECTED&quot; suffixes indicate inferential (not confirmed) classifications.
        </p>
      </div>
    </div>
  );
}
