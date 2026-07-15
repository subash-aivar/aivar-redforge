"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listIncidents,
  severityColor,
  statusColor,
  formatBps,
  formatPps,
  type DDoSIncident,
} from "@/lib/ddos";

const STATUS_OPTIONS = [
  { value: "", label: "All" },
  { value: "DETECTED", label: "Detected" },
  { value: "ACTIVE", label: "Active" },
  { value: "ESCALATED", label: "Escalated" },
  { value: "MITIGATING", label: "Mitigating" },
  { value: "MONITORING", label: "Monitoring" },
  { value: "RESOLVED", label: "Resolved" },
  { value: "CLOSED", label: "Closed" },
];

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

function DeviationBar({ multiplier }: { multiplier: number | null }) {
  if (!multiplier) return <span className="text-gray-500">—</span>;
  const clamped = Math.min(multiplier, 50);
  const pct = (clamped / 50) * 100;
  const color = multiplier >= 20 ? "bg-red-500" : multiplier >= 10 ? "bg-orange-500" : multiplier >= 5 ? "bg-yellow-500" : "bg-blue-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-gray-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-300">{multiplier.toFixed(1)}x</span>
    </div>
  );
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<DDoSIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");

  const load = async (status: string) => {
    try {
      const params = status ? { status: [status] } : undefined;
      const data = await listIncidents(params);
      setIncidents(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(statusFilter);
    const iv = setInterval(() => load(statusFilter), 20_000);
    return () => clearInterval(iv);
  }, [statusFilter]);

  const activeIncidents = incidents.filter(i =>
    ["DETECTED", "ACTIVE", "ESCALATED", "MITIGATING", "MONITORING"].includes(i.status)
  );

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">DDoS Incidents</h1>
          <p className="mt-1 text-sm text-gray-400">
            {activeIncidents.length > 0
              ? `${activeIncidents.length} active incident${activeIncidents.length !== 1 ? "s" : ""} — evidence-based detection from real telemetry`
              : "No active incidents — all resources within normal bounds"}
          </p>
        </div>
        <Link href="/ddos" className="text-sm text-blue-400 hover:underline">← DDoS Overview</Link>
      </div>

      {/* Status filter */}
      <div className="flex gap-2 flex-wrap">
        {STATUS_OPTIONS.map(opt => (
          <button
            key={opt.value}
            onClick={() => setStatusFilter(opt.value)}
            className={`rounded-full border px-3 py-1 text-xs font-semibold transition-colors ${
              statusFilter === opt.value
                ? "border-blue-600 bg-blue-900 text-blue-300"
                : "border-gray-700 bg-gray-800 text-gray-400 hover:border-gray-600"
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-500">
          Loading incidents…
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-4 text-red-300">{error}</div>
      )}

      {!loading && !error && incidents.length === 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center">
          <div className="text-4xl mb-4">⛨</div>
          <div className="text-lg font-medium text-gray-300">No incidents</div>
          <div className="mt-1 text-sm text-gray-500">
            {statusFilter ? `No ${statusFilter} incidents found` : "No DDoS incidents detected yet"}
          </div>
        </div>
      )}

      {!loading && incidents.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900 text-gray-400">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Resource</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-left font-medium">Severity</th>
                <th className="px-4 py-3 text-left font-medium">Classification</th>
                <th className="px-4 py-3 text-left font-medium">Peak BPS</th>
                <th className="px-4 py-3 text-left font-medium">Peak PPS</th>
                <th className="px-4 py-3 text-left font-medium">Deviation</th>
                <th className="px-4 py-3 text-left font-medium">Sources</th>
                <th className="px-4 py-3 text-left font-medium">Detected</th>
                <th className="px-4 py-3 text-left font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-950">
              {incidents.map(inc => {
                const duration = Math.floor(
                  (Date.now() - new Date(inc.first_detected_at).getTime()) / 60_000
                );
                return (
                  <tr key={inc.id} className={`hover:bg-gray-900 ${inc.status === "DETECTED" || inc.status === "ACTIVE" || inc.status === "ESCALATED" ? "bg-gray-950" : ""}`}>
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{inc.resource_name}</div>
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3 text-gray-300 text-xs">{inc.classification?.replace(/_/g, " ")}</td>
                    <td className="px-4 py-3 font-mono text-gray-300 text-xs">{formatBps(inc.peak_bytes_per_second)}</td>
                    <td className="px-4 py-3 font-mono text-gray-300 text-xs">{formatPps(inc.peak_packets_per_second)}</td>
                    <td className="px-4 py-3">
                      <DeviationBar multiplier={inc.peak_deviation_multiplier} />
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">
                      {inc.peak_unique_src_ips != null ? inc.peak_unique_src_ips.toLocaleString() : "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      <div>{new Date(inc.first_detected_at).toLocaleString()}</div>
                      {inc.resolved_at && (
                        <div className="text-emerald-600">{duration}m ago</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        href={`/ddos/incidents/${inc.id}`}
                        className="rounded border border-blue-800 bg-blue-950 px-3 py-1 text-xs font-medium text-blue-300 hover:bg-blue-900"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
