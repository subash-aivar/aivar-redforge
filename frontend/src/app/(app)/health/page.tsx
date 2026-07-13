"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { RuntimeHealth, ReadinessCheck } from "@/lib/types";

export default function HealthPage() {
  const [health, setHealth] = useState<RuntimeHealth | null>(null);
  const [readiness, setReadiness] = useState<ReadinessCheck | null>(null);
  const [runtimeHealth, setRuntimeHealth] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      api.get<RuntimeHealth>("/api/v1/health"),
      api.get<ReadinessCheck>("/api/v1/health/ready"),
      api.get<Record<string, unknown>>("/api/v1/runtime/health"),
    ]).then(([h, r, rt]) => {
      if (h.status === "fulfilled") setHealth(h.value);
      if (r.status === "fulfilled") setReadiness(r.value);
      if (rt.status === "fulfilled") setRuntimeHealth(rt.value);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-500">Loading health data...</div>;

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Platform Health</h1>
      <p className="mt-1 text-sm text-gray-400">Runtime and infrastructure status</p>

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Application</h2>
          <div className="mt-3 space-y-2">
            <Row label="Status" value={health?.status || "unknown"} ok={health?.status === "healthy"} />
            <Row label="Version" value={health?.version || "—"} />
            <Row label="Timestamp" value={health?.timestamp ? new Date(health.timestamp).toLocaleString() : "—"} />
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Readiness</h2>
          <div className="mt-3 space-y-2">
            <Row label="Overall" value={readiness?.status || "unknown"} ok={readiness?.status === "ready"} />
            {readiness?.checks && Object.entries(readiness.checks).map(([k, v]) => (
              <Row key={k} label={k} value={v} ok={v === "ok"} />
            ))}
          </div>
        </div>

        {runtimeHealth && (
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 lg:col-span-2">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Runtime Details</h2>
            <pre className="mt-3 overflow-auto rounded-lg bg-gray-950 p-3 text-xs text-gray-300">
              {JSON.stringify(runtimeHealth, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function Row({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-300">{label}</span>
      <span className={`text-sm font-medium ${ok === true ? "text-green-400" : ok === false ? "text-red-400" : "text-gray-400"}`}>
        {value}
      </span>
    </div>
  );
}
