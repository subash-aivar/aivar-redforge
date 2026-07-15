"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listProtectedResources,
  listTrafficWindows,
  formatBps,
  formatPps,
  severityColor,
  type ProtectedResource,
  type ObservationWindow,
} from "@/lib/ddos";

function MiniChart({ windows, field, color }: {
  windows: ObservationWindow[];
  field: "total_bytes_in" | "total_bytes_out" | "unique_src_ips";
  color: string;
}) {
  if (windows.length < 2) return null;

  const values = windows.map(w => {
    if (field === "unique_src_ips") return w.unique_src_ips;
    return (w[field] ?? 0);
  });
  const max = Math.max(...values, 1);

  const W = 320, H = 60;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - (v / max) * H;
    return `${x},${y}`;
  });
  const polygon = `0,${H} ${pts.join(" ")} ${W},${H}`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-12" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad_${field}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0.05" />
        </linearGradient>
      </defs>
      <polygon points={polygon} fill={`url(#grad_${field})`} />
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

export default function TrafficAnalyticsPage() {
  const [resources, setResources] = useState<ProtectedResource[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [windows, setWindows] = useState<ObservationWindow[]>([]);
  const [hours, setHours] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listProtectedResources().then(r => {
      setResources(r);
      if (r.length > 0) setSelectedId(r[0].id);
    }).catch(e => setError(e.message));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    setLoading(true);
    listTrafficWindows(selectedId, hours)
      .then(w => { setWindows(w); setError(null); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));

    const iv = setInterval(() => {
      listTrafficWindows(selectedId, hours).then(setWindows).catch(() => {});
    }, 60_000);
    return () => clearInterval(iv);
  }, [selectedId, hours]);

  const latestWindow = windows[windows.length - 1];
  const attackWindows = windows.filter(w => w.detection_fired);

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Traffic Analytics</h1>
          <p className="mt-1 text-sm text-gray-400">
            Real aggregation from telemetry_events · 1-minute windows
          </p>
        </div>
        <Link href="/ddos" className="text-sm text-blue-400 hover:underline">← DDoS Overview</Link>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Resource:</label>
          <select
            value={selectedId}
            onChange={e => setSelectedId(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
          >
            {resources.map(r => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Window:</label>
          {[1, 6, 24].map(h => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                hours === h
                  ? "border-blue-600 bg-blue-900 text-blue-300"
                  : "border-gray-700 bg-gray-800 text-gray-400 hover:border-gray-600"
              }`}
            >
              {h}h
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-4 text-red-300">{error}</div>
      )}

      {resources.length === 0 && !loading && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center">
          <div className="text-4xl mb-4">▣</div>
          <div className="text-lg font-medium text-gray-300">No protected resources configured</div>
          <div className="mt-2">
            <Link href="/ddos/protected-resources" className="text-sm text-blue-400 hover:underline">
              Configure Protected Resources →
            </Link>
          </div>
        </div>
      )}

      {selectedId && !loading && (
        <>
          {/* Current metrics */}
          {latestWindow && (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
                <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Current BPS (in)</div>
                <div className="mt-1 text-xl font-bold text-white font-mono">
                  {formatBps(latestWindow.total_bytes_in != null ? latestWindow.total_bytes_in / 60 : null)}
                </div>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
                <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Event Count</div>
                <div className="mt-1 text-xl font-bold text-white font-mono">
                  {latestWindow.event_count.toLocaleString()}
                </div>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
                <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Unique Sources</div>
                <div className="mt-1 text-xl font-bold text-white font-mono">
                  {latestWindow.unique_src_ips.toLocaleString()}
                </div>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
                <div className="text-xs font-semibold uppercase tracking-wider text-gray-500">Alerts (last window)</div>
                <div className="mt-1 text-xl font-bold text-white font-mono">
                  {latestWindow.alert_count.toLocaleString()}
                </div>
              </div>
            </div>
          )}

          {/* Attack detection summary */}
          {attackWindows.length > 0 && (
            <div className="rounded-xl border border-red-900 bg-red-950 p-4">
              <div className="flex items-center gap-2 text-red-300 font-semibold">
                <span>⚡</span>
                <span>{attackWindows.length} detection{attackWindows.length !== 1 ? "s" : ""} in the selected window</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {[...new Set(attackWindows.map(w => w.classification).filter(Boolean))].map(cls => (
                  <span key={cls} className="rounded bg-red-900 px-2 py-0.5 text-xs text-red-300">
                    {cls?.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Traffic chart */}
          {windows.length === 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-500">
              No traffic data for the selected resource and time window.
              <div className="mt-1 text-xs">
                Traffic windows are populated as telemetry events are ingested.
              </div>
            </div>
          )}

          {windows.length > 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-950 p-5">
              <h3 className="mb-4 text-sm font-semibold text-gray-300">Inbound Bytes — {windows.length} windows</h3>
              <MiniChart windows={windows} field="total_bytes_in" color="#60a5fa" />

              <h3 className="mb-4 mt-6 text-sm font-semibold text-gray-300">Unique Source IPs</h3>
              <MiniChart windows={windows} field="unique_src_ips" color="#f59e0b" />

              {/* Window table */}
              <h3 className="mb-3 mt-6 text-sm font-semibold text-gray-300">Window Detail (last 20)</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="text-gray-500">
                    <tr>
                      <th className="px-2 py-1.5 text-left">Window Start</th>
                      <th className="px-2 py-1.5 text-right">Events</th>
                      <th className="px-2 py-1.5 text-right">Bytes In</th>
                      <th className="px-2 py-1.5 text-right">Src IPs</th>
                      <th className="px-2 py-1.5 text-right">Alerts</th>
                      <th className="px-2 py-1.5 text-left">Detection</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {[...windows].reverse().slice(0, 20).map(w => (
                      <tr key={w.id} className={w.detection_fired ? "bg-red-950/30" : ""}>
                        <td className="px-2 py-1.5 font-mono text-gray-400">
                          {new Date(w.window_start_ts).toLocaleTimeString()}
                        </td>
                        <td className="px-2 py-1.5 text-right text-gray-300">{w.event_count.toLocaleString()}</td>
                        <td className="px-2 py-1.5 text-right font-mono text-gray-300">
                          {formatBps(w.total_bytes_in != null ? w.total_bytes_in / 60 : null)}
                        </td>
                        <td className="px-2 py-1.5 text-right text-gray-300">{w.unique_src_ips}</td>
                        <td className="px-2 py-1.5 text-right text-gray-400">{w.alert_count}</td>
                        <td className="px-2 py-1.5">
                          {w.detection_fired ? (
                            <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${severityColor(w.severity ?? "")}`}>
                              {w.severity}
                            </span>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
