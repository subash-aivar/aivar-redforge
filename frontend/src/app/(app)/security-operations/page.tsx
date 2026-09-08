"use client";

import Link from "next/link";
import { useCallback, useState } from "react";
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
import { PageHeader } from "@/components/cc";
import { getProductEdition } from "@/lib/productEdition";
import { usePlatformEventBus } from "@/components/platform/EventBusProvider";
import { entityLink } from "@/lib/eventEntityLink";
import { useLivePoll } from "@/lib/useLivePoll";
import { ConnectionIndicator, RealtimeTimestamp } from "@/components/platform/LiveIndicators";
import { listIncidents, severityColor as ddosSeverityColor, type DDoSIncident } from "@/lib/ddos";
import {
  listDetections,
  severityColor as behaviorSeverityColor,
  detectionTypeLabel,
  type BehaviorDetection,
} from "@/lib/behavior";
import {
  formatDateTime,
  importanceBadgeClass,
  phaseLabel,
  runtimeStatusBadgeClass,
  sourceDomainLabel,
} from "./security-operations-helpers";

function MetricCard({ label, value, tone = "default" }: { label: string; value: number; tone?: "default" | "danger" | "warning" }) {
  const toneClass =
    tone === "danger" && value > 0
      ? "text-red-400"
      : tone === "warning" && value > 0
        ? "text-amber-400"
        : "text-white";
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className={`text-3xl font-bold ${toneClass}`}>{value}</div>
      <div className="mt-1 text-sm font-medium text-gray-300">{label}</div>
    </div>
  );
}

function OperationalEventRow({ event, highlight }: { event: OperationalEvent; highlight?: boolean }) {
  const href = entityLink(event.entity_type, event.entity_id);
  const content = (
    <>
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
        <div className="mt-1 flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-wide text-gray-600">
            {sourceDomainLabel(event.source_domain)}
          </span>
          {href && <span className="text-[10px] font-medium text-red-400">Open →</span>}
        </div>
      </div>
    </>
  );
  const className = `flex items-start gap-3 border-b border-gray-800 py-3 last:border-0 transition-colors ${
    highlight ? "bg-red-950/10" : ""
  } ${href ? "hover:bg-gray-800/40" : ""}`;
  return href ? (
    <Link href={href} className={className}>
      {content}
    </Link>
  ) : (
    <div className={className}>{content}</div>
  );
}

function DdosIncidentRow({ incident }: { incident: DDoSIncident }) {
  const active = incident.status !== "resolved" && incident.status !== "closed";
  return (
    <Link
      href={`/ddos/incidents/${incident.id}`}
      className="flex items-center justify-between gap-3 border-b border-gray-800 py-2.5 last:border-0 hover:bg-gray-800/40"
    >
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-white">{incident.resource_name}</div>
        <div className="mt-0.5 text-xs text-gray-500">{incident.classification}</div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {active && <span className="h-2 w-2 animate-pulse rounded-full bg-red-400" title="active" />}
        <span className={`text-xs font-semibold uppercase ${ddosSeverityColor(incident.severity)}`}>
          {incident.severity}
        </span>
      </div>
    </Link>
  );
}

function BehaviorDetectionRow({ detection }: { detection: BehaviorDetection }) {
  return (
    <Link
      href={`/behavior/detections/${detection.id}`}
      className="flex items-center justify-between gap-3 border-b border-gray-800 py-2.5 last:border-0 hover:bg-gray-800/40"
    >
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-white">{detectionTypeLabel(detection.detection_type)}</div>
        <div className="mt-0.5 truncate text-xs text-gray-500">{detection.entity_id}</div>
      </div>
      <span className={`shrink-0 text-xs font-semibold uppercase ${behaviorSeverityColor(detection.severity)}`}>
        {detection.severity}
      </span>
    </Link>
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
  const [ddosIncidents, setDdosIncidents] = useState<DDoSIncident[]>([]);
  const [detections, setDetections] = useState<BehaviorDetection[]>([]);
  const [error, setError] = useState("");

  // Reads the shared connection from `EventBusProvider` rather than
  // opening a second independent SSE connection to the same endpoint
  // NotificationCenter and the Global Status Bar already subscribe to.
  const stream = usePlatformEventBus();

  // Defensive only (belt-and-suspenders): the backend is the authority —
  // network_defense's `/executions` routes are absent (404) server-side
  // regardless of what this client does. This just avoids issuing a
  // pointless request and rendering a panel with data that could never
  // arrive in this edition.
  const isFullEdition = getProductEdition() === "full";

  const load = useCallback(() => {
    Promise.all([
      getSummary("24h"),
      listChanges({ period: "24h", limit: 20 }),
      isFullEdition ? listExecutions({ limit: 20 }) : Promise.resolve([]),
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
    // DDoS/Behavior are fetched independently and degrade silently to an
    // empty list on failure (e.g. missing permission) rather than
    // blocking the rest of the command center on an unrelated context.
    listIncidents({ limit: 5 }).then(setDdosIncidents).catch(() => setDdosIncidents([]));
    listDetections({ limit: 5 }).then(setDetections).catch(() => setDetections([]));
  }, [isFullEdition]);

  useLivePoll(load, 15000);

  const liveFeed = [...stream.events].reverse().slice(0, 50);

  return (
    <div>
      <PageHeader
        title="Security Operations"
        subtitle="Live operational view over validation, drift, and runtime truth already produced by RedForge."
        actions={
          <div className="flex items-center gap-3">
            <ConnectionIndicator state={stream.connectionState} labels={{ connected: "Connected", reconnecting: "Reconnecting", disconnected: "Disconnected" }} />
            <span className="text-xs text-gray-500">
              <RealtimeTimestamp iso={stream.lastEventReceivedAt} prefix="Last event: " />
            </span>
          </div>
        }
      />

      {error ? (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          {/* Full-only cards — null (not 0) for network_defense, so these
              render only when the backend actually returned a real value. */}
          {summary.active_targets !== null && (
            <MetricCard label="Active Targets" value={summary.active_targets} />
          )}
          {summary.validations_running !== null && (
            <MetricCard label="Running Validations" value={summary.validations_running} />
          )}
          {summary.validations_blocked_in_period !== null && (
            <MetricCard
              label="Blocked (24h)"
              value={summary.validations_blocked_in_period}
              tone="warning"
            />
          )}
          <MetricCard label="Critical/High Conditions" value={summary.critical_high_conditions} tone="danger" />
          {summary.drift_events_in_period !== null && (
            <MetricCard label="Drift Events (24h)" value={summary.drift_events_in_period} tone="warning" />
          )}
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

      <div className={`mt-6 grid grid-cols-1 gap-6 ${isFullEdition ? "lg:grid-cols-3" : ""}`}>
        {isFullEdition ? (
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
        ) : null}

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

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">DDoS Activity</h2>
            <Link href="/ddos" className="text-xs text-gray-500 hover:text-gray-300">
              View all →
            </Link>
          </div>
          <div className="mt-3">
            {ddosIncidents.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">No DDoS incidents.</p>
            ) : (
              ddosIncidents.map((i) => <DdosIncidentRow key={i.id} incident={i} />)
            )}
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Behavior Detections</h2>
            <Link href="/behavior/detections" className="text-xs text-gray-500 hover:text-gray-300">
              View all →
            </Link>
          </div>
          <div className="mt-3">
            {detections.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">No behavior detections.</p>
            ) : (
              detections.map((d) => <BehaviorDetectionRow key={d.id} detection={d} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
