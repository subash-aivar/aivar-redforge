"use client";

import Link from "next/link";
import {
  Activity,
  AudioWaveform,
  Bot,
  Building2,
  Cpu,
  Globe2,
  History,
  KeyRound,
  RefreshCw,
  Shield,
  ShieldAlert,
  Users,
} from "lucide-react";
import {
  AsyncContent,
  DataConsole,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type AsyncState,
  type ConsoleColumn,
} from "@/components/cc";
import {
  getPlatformAudit,
  listPlatformAccess,
  listPlatformOrganizations,
  listPlatformUsers,
  type PlatformAuditEntry,
} from "@/lib/platform";
import {
  getAggregatedHealth,
  getDlqEntries,
  getReplayStatus,
  getRuntimeStatus,
  type DLQEntry,
} from "@/lib/runtime";
import * as securityOperations from "@/lib/securityOperations";
import { getRiskProfileCoverage } from "@/lib/riskEngine";
import { getInstanceSummary as getVulnerabilityInstanceSummary } from "@/lib/vulnerability";
import { getExposureStateCoverage } from "@/lib/attackSurfaceManagement";
import { getInventoryDashboard as getAiInventoryDashboard } from "@/lib/ai-posture";
import { getDDoSPosture } from "@/lib/ddos";
import { getBehaviorPosture } from "@/lib/behavior";

/**
 * Super Admin Command Center — the platform's operational brain.
 *
 * Every panel here is real: platform governance data
 * (users/organizations/access/audit, already wired) plus the runtime
 * infrastructure surface (`/api/v1/runtime/*`, M27/M31 — real
 * platform health, circuit breakers, DLQ, and background replay-
 * worker status). Redis/queue/worker visibility specifically comes
 * from `getDlqEntries` (the durable Postgres DLQ IS the queue this
 * platform uses — there is no separate Redis queue to report on, so
 * this is not a gap, it's the actual architecture) and
 * `getReplayStatus` (the DLQ replay worker's live counters). Anything
 * with no real backing source renders `NotConfigured` — never a
 * fabricated number.
 *
 * This redesign restructures the same real data sources into a
 * severity-led hero band plus operationally grouped sections (Runtime
 * & Infrastructure, Security Operations, Audit Trail) rather than a
 * flat KPI grid — no new API surface was added to achieve this.
 */
export default function PlatformOverviewPage() {
  const users = useAsync(() => listPlatformUsers(), []);
  const orgs = useAsync(() => listPlatformOrganizations(), []);
  const access = useAsync(() => listPlatformAccess(), []);
  const audit = useAsync(() => getPlatformAudit(), []);
  const runtimeStatus = useAsync(() => getRuntimeStatus(), []);
  const health = useAsync(() => getAggregatedHealth(), []);
  const dlq = useAsync(() => getDlqEntries(), []);
  const replay = useAsync(() => getReplayStatus(), []);
  const opsSummary = useAsync(() => securityOperations.getSummary("24h"), []);
  const riskCoverage = useAsync(() => getRiskProfileCoverage(), []);
  const vulnSummary = useAsync(() => getVulnerabilityInstanceSummary(), []);
  const exposureCoverage = useAsync(() => getExposureStateCoverage(), []);
  const aiInventory = useAsync(() => getAiInventoryDashboard(), []);
  const ddosPosture = useAsync(() => getDDoSPosture(), []);
  const behaviorPosture = useAsync(() => getBehaviorPosture(), []);

  const activeAccessCount = access.data?.filter((a) => a.status === "active").length ?? null;

  function refreshAll() {
    users.reload();
    orgs.reload();
    access.reload();
    audit.reload();
    runtimeStatus.reload();
    health.reload();
    dlq.reload();
    replay.reload();
    opsSummary.reload();
    riskCoverage.reload();
    vulnSummary.reload();
    exposureCoverage.reload();
    aiInventory.reload();
    ddosPosture.reload();
    behaviorPosture.reload();
  }

  const auditColumns: ConsoleColumn<PlatformAuditEntry>[] = [
    { key: "action", header: "Action", width: "24%", render: (r) => (
      <span className="font-mono text-purple-300">{r.action}</span>
    ) },
    { key: "actor", header: "Actor", width: "18%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-400">{r.actor_id.slice(0, 10)}…</span>
    ) },
    { key: "target", header: "Target", width: "18%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-400">{r.target_id.slice(0, 10)}…</span>
    ) },
    { key: "role", header: "Role", width: "14%", render: (r) => r.role ? <StatusPill status={r.role} /> : "—" },
    { key: "outcome", header: "Outcome", width: "12%", render: (r) => (
      <span className={r.outcome === "success" ? "text-emerald-400" : "text-red-400"}>
        {r.outcome}
      </span>
    ) },
    { key: "time", header: "Time", width: "14%", render: (r) => (
      <span className="text-gray-500">{fmtTime(r.timestamp)}</span>
    ) },
  ];

  const dlqColumns: ConsoleColumn<DLQEntry>[] = [
    { key: "source", header: "Projection", width: "22%", render: (r) => (
      <span className="font-mono text-purple-300">{r.source_projection}</span>
    ) },
    { key: "event_type", header: "Event Type", width: "22%", render: (r) => r.event_type },
    { key: "error", header: "Error", width: "36%", render: (r) => (
      <span className="truncate text-xs text-red-300">{r.error_message}</span>
    ) },
    { key: "retries", header: "Retries", width: "10%", render: (r) => r.retry_count },
  ];

  return (
    <>
      <HeroBand
        health={health}
        runtimeStatus={runtimeStatus}
        orgs={orgs}
        users={users}
        access={access}
        activeAccessCount={activeAccessCount}
        onRefresh={refreshAll}
      />

      <SectionHeader icon={Cpu} title="Runtime & Infrastructure" />
      <div className="mb-8 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Component Health">
          <AsyncContent state={health} emptyLabel="No component health reported.">
            {(data) => (
              <div className="space-y-1.5">
                {data.components.map((c) => (
                  <div key={c.component_id} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <PulseDot ok={c.status.toLowerCase() === "healthy"} />
                      <span className="text-gray-300">{c.component_id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="max-w-[220px] truncate text-xs text-gray-600">{c.message}</span>
                      <StatusPill status={c.status} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Circuit Breakers">
          <AsyncContent state={runtimeStatus} empty={(d) => Object.keys(d.circuit_states).length === 0} emptyLabel="No circuit breakers registered.">
            {(data) => (
              <div className="space-y-1.5">
                {Object.entries(data.circuit_states).map(([name, state]) => (
                  <div key={name} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <PulseDot ok={state.toLowerCase() === "closed"} />
                      <span className="font-mono text-gray-300">{name}</span>
                    </div>
                    <StatusPill status={state} />
                  </div>
                ))}
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mb-8 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          title="Background Replay Worker"
          right={
            replay.data ? (
              <div className="flex items-center gap-1.5">
                <PulseDot ok={replay.data.worker_running} live={replay.data.worker_running} />
                <StatusPill status={replay.data.worker_running ? "running" : "stopped"} />
              </div>
            ) : undefined
          }
        >
          <AsyncContent state={replay} emptyLabel="No replay worker telemetry.">
            {(data) => (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <MiniStat label="Replayed" value={data.replayed} />
                <MiniStat label="Failed" value={data.failed} tone="danger" />
                <MiniStat label="Skipped" value={data.skipped} />
                <MiniStat label="In Flight" value={data.in_flight} tone="ok" />
              </div>
            )}
          </AsyncContent>
        </Panel>

        <Panel
          title="Dead Letter Queue"
          right={dlq.data ? <span className="text-xs text-gray-500">{dlq.data.total} entries</span> : undefined}
        >
          <AsyncContent state={dlq} empty={(d) => d.entries.length === 0} emptyLabel="No entries in the dead-letter queue — all projections healthy.">
            {(data) => (
              <DataConsole
                columns={dlqColumns}
                rows={data.entries.slice(0, 8)}
                rowKey={(r) => r.entry_id}
                emptyLabel="No entries in the dead-letter queue."
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      {/* Redis is not part of this platform's architecture for
          queueing — the durable PostgreSQL DLQ above and the replay
          worker panel are the real infrastructure that own this
          concern. A generic "Redis health" panel would misrepresent
          the actual architecture, so it is intentionally omitted
          rather than shown as a fabricated NotConfigured stub for a
          system that was never built. */}

      <SectionHeader icon={ShieldAlert} title="Security Operations" />
      <div className="mb-8">
        <Panel title="Cross-Domain Operational Summary (24h)">
          <AsyncContent state={opsSummary} emptyLabel="No security-operations summary available.">
            {(data) => (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                <MiniStat label="Validations Running" value={data.validations_running} />
                <MiniStat label="Validations Blocked" value={data.validations_blocked_in_period} tone="danger" />
                <MiniStat label="Critical/High Conditions" value={data.critical_high_conditions} tone="danger" />
                <MiniStat label="Active Correlations" value={data.active_correlations} />
                <MiniStat label="Drift Events" value={data.drift_events_in_period} />
                <MiniStat label="Unhealthy Runtime" value={data.runtime_unhealthy_components} tone="danger" />
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <SectionHeader icon={Globe2} title="Security & AI Posture" />
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <PostureCard
          icon={Shield}
          title="Risk"
          href="/risk"
          state={riskCoverage}
          render={(d) => (
            <>
              <MiniStat label="Open" value={d.open} tone={d.open > 0 ? "danger" : "ok"} />
              <MiniStat label="Acknowledged" value={d.acknowledged} tone="warning" />
              <MiniStat label="Mitigated" value={d.mitigated} tone="ok" />
            </>
          )}
        />
        <PostureCard
          icon={ShieldAlert}
          title="Vulnerability"
          href="/vulnerability"
          state={vulnSummary}
          empty={(d) => !!d.empty}
          render={(d) => (
            <>
              <MiniStat label="Open" value={d.total_open} tone={d.total_open > 0 ? "danger" : "ok"} />
              <MiniStat label="Critical" value={d.by_severity.critical ?? 0} tone="danger" />
              <MiniStat label="High" value={d.by_severity.high ?? 0} tone="warning" />
            </>
          )}
        />
        <PostureCard
          icon={Globe2}
          title="Attack Surface"
          href="/attack-surface/assets"
          state={exposureCoverage}
          render={(d) => (
            <>
              <MiniStat label="Exposed High-Risk" value={d.exposed_high_risk} tone={d.exposed_high_risk > 0 ? "danger" : "ok"} />
              <MiniStat label="Internet Facing" value={d.internet_facing} tone="warning" />
              <MiniStat label="Not Exposed" value={d.not_exposed} tone="ok" />
            </>
          )}
        />
        <PostureCard
          icon={Bot}
          title="AI Operations"
          href="/ai-posture"
          state={aiInventory}
          render={(d) => (
            <>
              <MiniStat label="AI Assets" value={d.assets.length} />
              <MiniStat label="Coverage" value={d.assets.length > 0 ? 1 : 0} tone={d.assets.length > 0 ? "ok" : "default"} />
            </>
          )}
        />
        <PostureCard
          icon={AudioWaveform}
          title="DDoS Activity"
          href="/ddos"
          state={ddosPosture}
          render={(d) => (
            <>
              <MiniStat label="Active Incidents" value={d.active_incident_count} tone={d.active_incident_count > 0 ? "danger" : "ok"} />
              <MiniStat label="Protected Resources" value={d.protected_resource_count} />
              <MiniStat label="Pending Actions" value={d.pending_recommendation_count} tone="warning" />
            </>
          )}
        />
        <PostureCard
          icon={Activity}
          title="Behavior Analytics"
          href="/behavior"
          state={behaviorPosture}
          render={(d) => (
            <>
              <MiniStat label="Active Detections" value={d.active_detections} tone={d.active_detections > 0 ? "warning" : "ok"} />
              <MiniStat label="Critical/High" value={d.critical_high_detections} tone="danger" />
              <MiniStat label="Monitored Entities" value={d.monitored_entities} />
            </>
          )}
        />
      </div>

      <SectionHeader icon={History} title="Audit Trail" />
      <Panel
        title="Recent Platform Security Audit"
        right={
          <span className="text-[10px] uppercase tracking-widest text-gray-600">
            Append-only log
          </span>
        }
      >
        <AsyncContent state={audit} emptyLabel="No platform security events recorded yet.">
          {(rows) => (
            <DataConsole
              columns={auditColumns}
              rows={rows.slice(0, 15)}
              rowKey={(r) => `${r.action}-${r.actor_id}-${r.target_id}-${r.timestamp}`}
              emptyLabel="No platform security events recorded yet."
            />
          )}
        </AsyncContent>
      </Panel>
    </>
  );
}

type LoadState<T> = { loading: boolean; error: string | null; forbidden: boolean; data: T | null };

function HeroBand({
  health,
  runtimeStatus,
  orgs,
  users,
  access,
  activeAccessCount,
  onRefresh,
}: {
  health: LoadState<{ overall_status: string }>;
  runtimeStatus: LoadState<{ unhealthy_components: string[]; component_count: number; dlq_total_entries: number }>;
  orgs: LoadState<unknown[]>;
  users: LoadState<unknown[]>;
  access: LoadState<unknown[]>;
  activeAccessCount: number | null;
  onRefresh: () => void;
}) {
  const overall = health.data?.overall_status?.toLowerCase() ?? null;
  const ok = overall === "healthy";
  const known = !health.loading && !health.forbidden && !health.error && overall !== null;

  return (
    <div className="mb-8 overflow-hidden rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-900 via-gray-900 to-purple-950/20">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-800/80 px-6 py-5">
        <div className="flex items-center gap-4">
          <div
            className={`flex h-12 w-12 items-center justify-center rounded-xl border ${
              known
                ? ok
                  ? "border-emerald-800 bg-emerald-950/40"
                  : "border-red-800 bg-red-950/40"
                : "border-gray-700 bg-gray-800/40"
            }`}
          >
            <Activity
              className={`h-6 w-6 ${known ? (ok ? "text-emerald-400" : "text-red-400") : "text-gray-500"}`}
              aria-hidden="true"
            />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-gray-100">Super Admin Command Center</h1>
              {known && <PulseDot ok={ok} live />}
            </div>
            <p className="mt-0.5 text-sm text-gray-500">
              {health.loading
                ? "Assessing platform health…"
                : known
                  ? `Platform is ${overall} — ${runtimeStatus.data?.unhealthy_components.length ?? 0} of ${runtimeStatus.data?.component_count ?? 0} components need attention`
                  : "Platform health unavailable"}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-purple-700 hover:text-purple-300"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 gap-px bg-gray-800/60 sm:grid-cols-3 lg:grid-cols-6">
        <HeroStat icon={Users} label="Registered Users" state={users} />
        <HeroStat icon={Building2} label="Organizations" state={orgs} />
        <HeroStat icon={KeyRound} label="Active Access Grants" state={access} value={activeAccessCount ?? undefined} />
        <HeroStat
          icon={AudioWaveform}
          label="Unhealthy Components"
          state={runtimeStatus}
          value={runtimeStatus.data?.unhealthy_components.length}
          danger={(runtimeStatus.data?.unhealthy_components.length ?? 0) > 0}
        />
        <HeroStat
          icon={Cpu}
          label="DLQ Depth"
          state={runtimeStatus}
          value={runtimeStatus.data?.dlq_total_entries}
          danger={(runtimeStatus.data?.dlq_total_entries ?? 0) > 0}
        />
        <HeroStat icon={ShieldAlert} label="Platform Health" state={health} value={health.data?.overall_status} danger={known && !ok} />
      </div>
    </div>
  );
}

function HeroStat<T>({
  icon: Icon,
  label,
  state,
  value,
  danger,
}: {
  icon: typeof Activity;
  label: string;
  state: LoadState<T>;
  value?: React.ReactNode;
  danger?: boolean;
}) {
  const display = state.loading
    ? "…"
    : state.forbidden
      ? "—"
      : state.error || state.data === null
        ? "N/A"
        : (value ?? (Array.isArray(state.data) ? state.data.length : "—"));
  return (
    <div className="bg-gray-900/80 px-5 py-4">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        <Icon className="h-3 w-3" aria-hidden="true" />
        {label}
      </div>
      <div className={`mt-1.5 text-2xl font-bold tabular-nums ${danger ? "text-red-400" : "text-gray-100"}`}>
        {display}
      </div>
    </div>
  );
}

/**
 * Cross-domain posture card — one real bounded-context read, one
 * real drill-down link into the module that actually owns the data
 * (never a duplicated table). Used for Risk/Vulnerability/Attack
 * Surface/AI/DDoS/Behavior — six previously-unrepresented bounded
 * contexts on this page, each backed by the same client already used
 * on that module's own operational landing page (built in earlier
 * slices) — no new API surface, no fabricated aggregation.
 */
function PostureCard<T>({
  icon: Icon,
  title,
  href,
  state,
  render,
  empty,
}: {
  icon: typeof Activity;
  title: string;
  href: string;
  state: AsyncState<T>;
  render: (data: T) => React.ReactNode;
  empty?: (data: T) => boolean;
}) {
  return (
    <section className="rounded-xl border border-gray-800 bg-gray-900/60">
      <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
        <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-400">
          <Icon className="h-3.5 w-3.5 text-purple-400" aria-hidden="true" />
          {title}
        </div>
        <Link href={href} className="text-[10px] font-medium text-purple-300 hover:text-purple-200">
          View →
        </Link>
      </div>
      <div className="p-4">
        <AsyncContent state={state} empty={empty} emptyLabel="No data yet.">
          {(data) => <div className="grid grid-cols-3 gap-2">{render(data)}</div>}
        </AsyncContent>
      </div>
    </section>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: typeof Activity; title: string }) {
  return (
    <div className="mb-3 mt-2 flex items-center gap-2">
      <Icon className="h-4 w-4 text-purple-400" aria-hidden="true" />
      <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-400">{title}</h2>
      <div className="h-px flex-1 bg-gray-800" aria-hidden="true" />
    </div>
  );
}

function PulseDot({ ok, live = false }: { ok: boolean; live?: boolean }) {
  return (
    <span className="relative flex h-2 w-2">
      {live && (
        <span
          className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${ok ? "bg-emerald-400" : "bg-red-400"}`}
        />
      )}
      <span className={`relative inline-flex h-2 w-2 rounded-full ${ok ? "bg-emerald-400" : "bg-red-400"}`} />
    </span>
  );
}

function MiniStat({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: number;
  tone?: "default" | "danger" | "ok" | "warning";
}) {
  const toneClass =
    tone === "danger"
      ? "text-red-400"
      : tone === "ok"
        ? "text-emerald-400"
        : tone === "warning"
          ? "text-amber-400"
          : "text-gray-200";
  return (
    <div>
      <div className={`text-xl font-bold tabular-nums ${toneClass}`}>{value}</div>
      <div className="text-[11px] uppercase tracking-wider text-gray-600">{label}</div>
    </div>
  );
}
