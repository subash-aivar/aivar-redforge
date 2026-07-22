"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { RuntimeHealth, ReadinessCheck, Target, Finding, RiskIncident } from "@/lib/types";
import { PlatformBootstrapCard } from "@/components/PlatformBootstrapCard";

export default function DashboardPage() {
  const [health, setHealth] = useState<RuntimeHealth | null>(null);
  const [readiness, setReadiness] = useState<ReadinessCheck | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [risk, setRisk] = useState<RiskIncident[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.allSettled([
      api.get<RuntimeHealth>("/api/v1/health"),
      api.get<ReadinessCheck>("/api/v1/health/ready"),
      api.get<Target[]>("/api/v1/targets"),
      api.get<Finding[]>("/api/v1/findings"),
      api.get<RiskIncident[]>("/api/v1/risk-incidents"),
    ]).then(([h, r, t, f, ri]) => {
      if (h.status === "fulfilled") setHealth(h.value);
      if (r.status === "fulfilled") setReadiness(r.value);
      if (t.status === "fulfilled") setTargets(Array.isArray(t.value) ? t.value : []);
      if (f.status === "fulfilled") setFindings(Array.isArray(f.value) ? f.value : []);
      if (ri.status === "fulfilled") setRisk(Array.isArray(ri.value) ? ri.value : []);
    }).catch(() => setError("Failed to load dashboard data"));
  }, []);

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Security Overview</h1>
      <p className="mt-1 text-sm text-gray-400">
        AI attack surface and security posture
      </p>

      {error && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="mt-4">
        <PlatformBootstrapCard />
      </div>

      {/* Metric cards */}
      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="AI Targets"
          value={targets.length}
          sublabel="Under validation"
          color="blue"
        />
        <MetricCard
          label="Critical Findings"
          value={criticalFindings.length}
          sublabel="Require immediate action"
          color="red"
        />
        <MetricCard
          label="High Findings"
          value={highFindings.length}
          sublabel="Security concerns"
          color="orange"
        />
        <MetricCard
          label="Risk Incidents"
          value={risk.length}
          sublabel="Active incidents"
          color="yellow"
        />
      </div>

      {/* Platform health */}
      <div className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
            Platform Status
          </h2>
          <div className="mt-3 space-y-2">
            <StatusRow label="Application" status={health?.status || "unknown"} />
            <StatusRow label="Database" status={readiness?.checks?.database || "unknown"} />
            <StatusRow label="Version" status={health?.version || "—"} />
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
            Recent Findings
          </h2>
          {findings.length === 0 ? (
            <p className="mt-3 text-sm text-gray-500">
              No findings yet. Run a red-team campaign to generate security findings.
            </p>
          ) : (
            <div className="mt-3 space-y-2">
              {findings.slice(0, 5).map((f) => (
                <div key={f.id} className="flex items-center justify-between text-sm">
                  <span className="text-gray-300 truncate max-w-[200px]">{f.title}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Targets overview */}
      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
          AI Targets
        </h2>
        {targets.length === 0 ? (
          <p className="mt-3 text-sm text-gray-500">
            No AI targets registered. Register a target to begin security validation.
          </p>
        ) : (
          <div className="mt-3 space-y-2">
            {targets.map((t) => (
              <div key={t.id} className="flex items-center justify-between rounded-lg border border-gray-800 px-4 py-2">
                <div>
                  <span className="text-sm font-medium text-gray-200">{t.name}</span>
                  <span className="ml-2 text-xs text-gray-500">{t.target_type} · {t.provider}</span>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded ${t.status === "active" ? "bg-green-950 text-green-400" : "bg-gray-800 text-gray-500"}`}>
                  {t.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function MetricCard({ label, value, sublabel, color }: {
  label: string; value: number; sublabel: string; color: string;
}) {
  const colors: Record<string, string> = {
    blue: "border-blue-800 text-blue-400",
    red: "border-red-800 text-red-400",
    orange: "border-orange-800 text-orange-400",
    yellow: "border-yellow-800 text-yellow-400",
  };
  return (
    <div className={`rounded-xl border bg-gray-900 p-5 ${colors[color] || "border-gray-800"}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="mt-1 text-sm font-medium text-gray-300">{label}</div>
      <div className="text-xs text-gray-500">{sublabel}</div>
    </div>
  );
}

function StatusRow({ label, status }: { label: string; status: string }) {
  const ok = status === "healthy" || status === "ok" || status === "ready";
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-300">{label}</span>
      <span className={`text-xs font-medium ${ok ? "text-green-400" : "text-yellow-400"}`}>
        {status}
      </span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-950 text-red-400",
    high: "bg-orange-950 text-orange-400",
    medium: "bg-yellow-950 text-yellow-400",
    low: "bg-blue-950 text-blue-400",
    informational: "bg-gray-800 text-gray-400",
  };
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium ${colors[severity] || "bg-gray-800 text-gray-400"}`}>
      {severity}
    </span>
  );
}
