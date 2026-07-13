"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  getSummary,
  listChanges,
  listExecutions,
  listRuntimeComponents,
  type ExecutionTelemetrySummary,
  type OperationalEvent,
  type RuntimeComponent,
  type SecurityOperationsSummary,
} from "@/lib/securityOperations";
import { useSecurityOperationsStream } from "@/lib/useSecurityOperationsStream";
import {
  formatDateTime,
  importanceBadgeClass,
  phaseLabel,
  runtimeStatusBadgeClass,
  sourceDomainLabel,
} from "./security-operations-helpers";

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className="text-3xl font-bold text-white">{value}</div>
      <div className="mt-1 text-sm font-medium text-gray-300">{label}</div>
    </div>
  );
}

function ConnectionBadge({ state }: { state: "connected" | "reconnecting" | "disconnected" }) {
  const styles: Record<string, string> = {
    connected: "border-emerald-800 bg-emerald-950 text-emerald-400",
    reconnecting: "border-amber-800 bg-amber-950 text-amber-400",
    disconnected: "border-gray-700 bg-gray-800 text-gray-400",
  };
  const labels: Record<string, string> = {
    connected: "CONNECTED",
    reconnecting: "RECONNECTING",
    disconnected: "DISCONNECTED",
  };
  return (
    <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${styles[state]}`}>
      {labels[state]}
    </span>
  );
}

function OperationalEventRow({ event }: { event: OperationalEvent }) {
  return (
    <div className="flex items-start gap-3 border-b border-gray-800 py-3 last:border-0">
      <span
        className={`mt-0.5 rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${importanceBadgeClass(event.importance)}`}
      >
        {event.importance}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-sm font-medium text-white">{event.title}</span>
          <span className="shrink-0 text-xs text-gray-500">
            {formatDateTime(event.occurred_at)}
          </span>
        </div>
        <div className="mt-0.5 text-xs text-gray-400">{event.summary}</div>
        <div className="mt-1 text-[10px] uppercase tracking-wide text-gray-600">
          {sourceDomainLabel(event.source_domain)}
        </div>
      </div>
    </div>
  );
}

function ExecutionRow({ execution }: { execution: ExecutionTelemetrySummary }) {
  const nonTerminal = ["pending", "policy_checking", "authorized", "running"].includes(
    execution.state
  );
  return (
    <Link
      href={`/security-operations/executions/${execution.id}`}
      className="flex items-center justify-between gap-3 border-b border-gray-800 py-3 last:border-0 hover:bg-gray-800/40"
    >
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-white">
          {execution.target_id} — {phaseLabel(execution.phase)}
        </div>
        <div className="mt-0.5 text-xs text-gray-500">
          {execution.trigger.toUpperCase()} · {execution.profile}
          {execution.latest_event_title ? ` · ${execution.latest_event_title}` : ""}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {nonTerminal ? (
          <span className="h-2 w-2 animate-pulse rounded-full bg-blue-400" title="in progress" />
        ) : null}
        <span className="text-xs uppercase text-gray-400">{execution.state}</span>
      </div>
    </Link>
  );
}

function RuntimeComponentRow({ component }: { component: RuntimeComponent }) {
  return (
    <div className="flex items-center justify-between border-b border-gray-800 py-2 last:border-0">
      <span className="text-sm text-gray-300">{component.component_id}</span>
      <span
        className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${runtimeStatusBadgeClass(component.status)}`}
      >
        {component.status}
      </span>
    </div>
  );
}

export default function SecurityOperationsPage() {
  const [summary, setSummary] = useState<SecurityOperationsSummary | null>(null);
  const [changes, setChanges] = useState<OperationalEvent[]>([]);
  const [executions, setExecutions] = useState<ExecutionTelemetrySummary[]>([]);
  const [runtime, setRuntime] = useState<RuntimeComponent[]>([]);
  const [error, setError] = useState("");

  const stream = useSecurityOperationsStream(true);

  const load = useCallback(() => {
    Promise.all([
      getSummary("24h"),
      listChanges({ period: "24h", limit: 20 }),
      listExecutions({ limit: 20 }),
      listRuntimeComponents(),
    ])
      .then(([s, c, e, r]) => {
        setSummary(s);
        setChanges(c);
        setExecutions(e);
        setRuntime(r);
        setError("");
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "UNAVAILABLE — failed to load.");
      });
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [load]);

  const liveFeed = [...stream.events].reverse().slice(0, 50);

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Operations</h1>
          <p className="text-sm text-gray-400">
            Live operational view over validation, drift, and runtime truth already produced by
            RedForge.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ConnectionBadge state={stream.connectionState} />
          <span className="text-xs text-gray-500">
            Last event: {formatDateTime(stream.lastEventReceivedAt)}
          </span>
        </div>
      </div>

      {error ? (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          <MetricCard label="Active Targets" value={summary.active_targets} />
          <MetricCard label="Running Validations" value={summary.validations_running} />
          <MetricCard label="Blocked (24h)" value={summary.validations_blocked_in_period} />
          <MetricCard label="Critical/High Conditions" value={summary.critical_high_conditions} />
          <MetricCard label="Drift Events (24h)" value={summary.drift_events_in_period} />
        </div>
      ) : null}

      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold text-white">Live Operations Feed</h2>
          <div className="mt-3 max-h-96 overflow-y-auto">
            {liveFeed.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">
                No live events yet — waiting for the stream…
              </p>
            ) : (
              liveFeed.map((e) => <OperationalEventRow key={e.event_id} event={e} />)
            )}
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold text-white">Security Change Feed</h2>
          <div className="mt-3 max-h-96 overflow-y-auto">
            {changes.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">No changes in this period.</p>
            ) : (
              changes.map((e) => <OperationalEventRow key={e.event_id} event={e} />)
            )}
          </div>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold text-white">Active Executions</h2>
          <div className="mt-3">
            {executions.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">No recent executions.</p>
            ) : (
              executions.map((e) => <ExecutionRow key={e.id} execution={e} />)
            )}
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-sm font-semibold text-white">Runtime Components</h2>
          <div className="mt-3">
            {runtime.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">No components registered.</p>
            ) : (
              runtime.map((c) => <RuntimeComponentRow key={c.component_id} component={c} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
