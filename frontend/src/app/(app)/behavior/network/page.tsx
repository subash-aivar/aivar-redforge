"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  getNetworkRelationships,
  formatBytes,
  type NetworkRelationship,
} from "@/lib/behavior";

// RFC-1918 check replicated client-side (not exported from lib)
const RFC1918 = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
  "172.30.", "172.31.", "192.168."];
function isInternal(ip: string) {
  return RFC1918.some(p => ip.startsWith(p));
}

export default function NetworkRelationshipsPage() {
  const [data, setData] = useState<{ edges: NetworkRelationship[]; total: number } | null>(null);
  const [hours, setHours] = useState(24);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "internal" | "external">("all");

  useEffect(() => {
    setLoading(true);
    getNetworkRelationships(hours, 200)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [hours]);

  const edges = data?.edges ?? [];
  const filtered = edges.filter((e) => {
    if (filter === "internal") return isInternal(e.src_ip) && isInternal(e.dst_ip ?? "");
    if (filter === "external") return !isInternal(e.dst_ip ?? "");
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Network Relationships</h1>
          <p className="text-sm text-gray-400">
            Communication pairs from canonical telemetry_events — observed, not inferred
          </p>
        </div>
        <Link href="/behavior" className="text-sm text-cyan-400 hover:text-cyan-300">← Overview</Link>
      </div>

      <div className="flex flex-wrap gap-2">
        <div className="flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
          {[24, 6, 1].map((h) => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                hours === h
                  ? "bg-cyan-900 text-cyan-300"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {h}h
            </button>
          ))}
        </div>
        <div className="flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
          {(["all", "internal", "external"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-colors ${
                filter === f
                  ? "bg-cyan-900 text-cyan-300"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="flex items-center text-xs text-gray-500">
          {filtered.length} relationships shown
        </div>
      </div>

      {loading ? (
        <div className="py-12 text-center text-gray-500">Loading network relationships…</div>
      ) : error ? (
        <div className="rounded-xl border border-red-800 bg-red-950/30 p-4 text-red-400">{error}</div>
      ) : filtered.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 py-12 text-center">
          <div className="text-2xl text-gray-700">⊘</div>
          <div className="mt-2 text-sm text-gray-500">No relationships in this time window</div>
        </div>
      ) : (
        <div className="rounded-xl border border-gray-800 bg-gray-900">
          <div className="border-b border-gray-800 px-5 py-3 grid grid-cols-6 gap-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            <div className="col-span-2">Source</div>
            <div className="col-span-2">Destination</div>
            <div>Events</div>
            <div>Bytes Out</div>
          </div>
          <div className="divide-y divide-gray-800/50 max-h-[60vh] overflow-y-auto">
            {filtered.map((edge, i) => {
              const internal = isInternal(edge.src_ip) && isInternal(edge.dst_ip ?? "");
              return (
                <div
                  key={`${edge.src_ip}-${edge.dst_ip}-${edge.dst_port}-${i}`}
                  className="grid grid-cols-6 gap-3 items-center px-5 py-2.5"
                >
                  <div className="col-span-2">
                    <Link
                      href={`/behavior/entities/${encodeURIComponent(edge.src_ip)}`}
                      className="font-mono text-sm text-cyan-300 hover:text-cyan-200"
                    >
                      {edge.src_ip}
                    </Link>
                  </div>
                  <div className="col-span-2 flex items-center gap-1">
                    <span className="font-mono text-sm text-gray-300">
                      {edge.dst_ip ?? "—"}
                      {edge.dst_port ? `:${edge.dst_port}` : ""}
                    </span>
                    {internal && (
                      <span className="rounded border border-pink-700 bg-pink-950 px-1.5 py-0.5 text-xs text-pink-400">
                        INT
                      </span>
                    )}
                    {edge.protocol && (
                      <span className="text-xs text-gray-600">{edge.protocol.toUpperCase()}</span>
                    )}
                  </div>
                  <div className="text-sm text-gray-300">{edge.event_count.toLocaleString()}</div>
                  <div className="text-sm text-gray-400">{formatBytes(edge.total_bytes_out)}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="rounded-xl border border-gray-800 bg-gray-900/50 px-4 py-3 text-xs text-gray-600">
        All relationships are OBSERVED from canonical telemetry_events. No inferred or suspected
        edges are shown here. INT = both IPs in RFC-1918 space.
      </div>
    </div>
  );
}
