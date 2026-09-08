"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { FormField, FormModal } from "@/components/cc";
import {
  getInvestigation,
  getInvestigationTimeline,
  getInvestigationEvidence,
  acknowledgeInvestigation,
  startInvestigation,
  resolveInvestigation,
  listInvestigationAttackPaths,
  recomputeInvestigationAttackPath,
  severityColor,
  confidenceColor,
  statusColor,
  domainColor,
  domainLabel,
  formatTs,
  type InvestigationCase,
  type EvidenceLink,
  type InvestigationTimelineEvent,
  type LinkedAttackPath,
} from "@/lib/investigations";

type Tab = "timeline" | "evidence" | "paths";

const RESOLUTION_REASONS = [
  "TRUE_POSITIVE_REMEDIATED",
  "TRUE_POSITIVE_ACCEPTED_RISK",
  "FALSE_POSITIVE",
  "BENIGN_ACTIVITY",
  "DUPLICATE",
  "INSUFFICIENT_EVIDENCE",
  "EXPIRED",
];

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();

  const [inv, setInv] = useState<InvestigationCase | null>(null);
  const [timeline, setTimeline] = useState<InvestigationTimelineEvent[]>([]);
  const [evidence, setEvidence] = useState<EvidenceLink[]>([]);
  const [paths, setPaths] = useState<LinkedAttackPath[]>([]);
  const [tab, setTab] = useState<Tab>("timeline");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actioning, setActioning] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [resolveOpen, setResolveOpen] = useState(false);
  const [resolveReason, setResolveReason] = useState(RESOLUTION_REASONS[0]);
  const [resolveNotes, setResolveNotes] = useState("");
  const [resolveError, setResolveError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [c, tl, ev, ap] = await Promise.all([
        getInvestigation(id),
        getInvestigationTimeline(id),
        getInvestigationEvidence(id),
        listInvestigationAttackPaths(id).catch(() => [] as LinkedAttackPath[]),
      ]);
      setInv(c);
      setTimeline(tl);
      setEvidence(ev);
      setPaths(ap);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load investigation");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleAcknowledge() {
    setActioning(true);
    setActionError(null);
    try { await acknowledgeInvestigation(id); await load(); }
    catch (e) { setActionError(e instanceof Error ? e.message : "Acknowledge failed"); }
    finally { setActioning(false); }
  }

  async function handleStartInvestigation() {
    setActioning(true);
    setActionError(null);
    try { await startInvestigation(id); await load(); }
    catch (e) { setActionError(e instanceof Error ? e.message : "Start investigation failed"); }
    finally { setActioning(false); }
  }

  function openResolveModal() {
    setResolveReason(RESOLUTION_REASONS[0]);
    setResolveNotes("");
    setResolveError(null);
    setResolveOpen(true);
  }

  function closeResolveModal() {
    setResolveOpen(false);
  }

  async function handleResolve(e: React.FormEvent) {
    e.preventDefault();
    setActioning(true);
    setResolveError(null);
    try {
      await resolveInvestigation(id, resolveReason, resolveNotes);
      setResolveOpen(false);
      await load();
    } catch (err) {
      setResolveError(err instanceof Error ? err.message : "Resolve failed");
    } finally {
      setActioning(false);
    }
  }

  function eventTypeLabel(type: string): string {
    return type.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
  }

  if (loading) {
    return (
      <div className="p-6 text-center text-sm text-gray-500">Loading investigation…</div>
    );
  }

  if (error || !inv) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-red-800 bg-red-900/20 p-4 text-sm text-red-300">
          {error ?? "Investigation not found"}
        </div>
        <button onClick={() => router.back()} className="mt-4 text-sm text-gray-400 hover:text-white">
          ← Back
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link href="/investigations" className="text-xs text-gray-500 hover:text-gray-300">
            ← Investigations
          </Link>
          <h1 className="mt-2 text-xl font-bold text-white">{inv.title}</h1>
          <p className="mt-1 text-sm text-gray-400">{inv.summary}</p>
        </div>
        <div className="flex shrink-0 gap-2">
          {inv.status === "OPEN" && (
            <button
              onClick={handleAcknowledge}
              disabled={actioning}
              className="rounded border border-yellow-700 bg-yellow-900/20 px-3 py-1.5 text-xs font-medium text-yellow-300 hover:bg-yellow-900/40 disabled:opacity-50"
            >
              Acknowledge
            </button>
          )}
          {(inv.status === "OPEN" || inv.status === "ACKNOWLEDGED") && (
            <button
              onClick={handleStartInvestigation}
              disabled={actioning}
              className="rounded border border-blue-700 bg-blue-900/20 px-3 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-900/40 disabled:opacity-50"
            >
              Start Investigation
            </button>
          )}
          {inv.status !== "RESOLVED" && (
            <button
              onClick={openResolveModal}
              disabled={actioning}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-700 disabled:opacity-50"
            >
              Resolve
            </button>
          )}
        </div>
      </div>

      {actionError && (
        <div role="alert" className="rounded-lg border border-red-800 bg-red-900/20 p-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {/* Case metadata */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <MetaCard label="Status">
          <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(inv.status)}`}>
            {inv.status}
          </span>
        </MetaCard>
        <MetaCard label="Severity">
          <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${severityColor(inv.severity)}`}>
            {inv.severity}
          </span>
        </MetaCard>
        <MetaCard label="Confidence">
          <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${confidenceColor(inv.confidence)}`}>
            {inv.confidence.replace("_", " ")}
          </span>
        </MetaCard>
        <MetaCard label="Evidence">
          <span className="text-lg font-bold text-white">{inv.evidence_count}</span>
        </MetaCard>
        <MetaCard label="Domains">
          <div className="flex flex-wrap gap-1">
            {(inv.source_domains ?? []).map((d) => (
              <span key={d} className={`rounded border px-1.5 py-0.5 text-xs ${domainColor(d)}`}>
                {domainLabel(d)}
              </span>
            ))}
          </div>
        </MetaCard>
        <MetaCard label="First Observed">
          <span className="text-xs text-gray-300">{formatTs(inv.first_observed_at)}</span>
        </MetaCard>
      </div>

      {/* Entities */}
      {inv.involved_entities && inv.involved_entities.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Involved Entities
          </div>
          <div className="flex flex-wrap gap-2">
            {inv.involved_entities.map((e, i) => (
              <div
                key={i}
                className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs"
              >
                <span className="text-gray-500">{e.type}: </span>
                <span className="font-mono text-gray-200">{e.id}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {(["timeline", "evidence", "paths"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium capitalize ${
              tab === t
                ? "border-b-2 border-blue-500 text-white"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "paths"
              ? `attack paths (${paths.length})`
              : t === "evidence"
                ? `evidence (${evidence.length})`
                : `timeline (${timeline.length})`}
          </button>
        ))}
      </div>

      {tab === "paths" && (
        <div className="space-y-3">
          <div className="flex justify-end">
            <button
              type="button"
              disabled={actioning}
              onClick={async () => {
                setActioning(true);
                try {
                  await recomputeInvestigationAttackPath(id, true);
                  await load();
                } finally {
                  setActioning(false);
                }
              }}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-50"
            >
              Recompute path
            </button>
          </div>
          {paths.length === 0 ? (
            <div className="py-8 text-center text-sm text-gray-500">
              No linked attack paths yet
            </div>
          ) : (
            paths.map((p) => (
              <Link
                key={p.id}
                href={`/attack-paths/${p.id}`}
                className="block rounded-lg border border-gray-800 bg-gray-900 p-4 hover:border-gray-700"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-white">
                    {p.root_canonical_key}
                  </span>
                  <span className="text-xs text-gray-400">{p.path_confidence}</span>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  {p.step_count} steps · {p.technique_coverage.join(", ") || "no techniques"}
                </div>
              </Link>
            ))
          )}
        </div>
      )}

      {/* Timeline */}
      {tab === "timeline" && (
        <div className="space-y-2">
          {timeline.length === 0 ? (
            <div className="text-center text-sm text-gray-500 py-8">No timeline events yet</div>
          ) : (
            timeline.map((ev) => (
              <div
                key={ev.id}
                className="flex gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4"
              >
                <div className="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-blue-500" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-white">
                      {eventTypeLabel(ev.event_type)}
                    </span>
                    <span className="shrink-0 text-xs text-gray-500">{formatTs(ev.occurred_at)}</span>
                  </div>
                  {ev.detail && Object.keys(ev.detail).length > 0 && (
                    <div className="mt-1 font-mono text-xs text-gray-400">
                      {Object.entries(ev.detail)
                        .filter(([k]) => k !== "actor_user_id")
                        .slice(0, 3)
                        .map(([k, v]) => (
                          <span key={k} className="mr-3">
                            <span className="text-gray-600">{k}:</span>{" "}
                            <span>{String(v)}</span>
                          </span>
                        ))}
                    </div>
                  )}
                  {ev.actor_user_id && (
                    <div className="mt-0.5 text-xs text-gray-600">by {ev.actor_user_id}</div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Evidence */}
      {tab === "evidence" && (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          {evidence.length === 0 ? (
            <div className="p-8 text-center text-sm text-gray-500">No evidence attached yet</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800 bg-gray-900">
                <tr className="text-left text-xs text-gray-500">
                  <th className="px-4 py-3">Domain</th>
                  <th className="px-4 py-3">Entity</th>
                  <th className="px-4 py-3">Event Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Observability</th>
                  <th className="px-4 py-3">Observed At</th>
                  <th className="px-4 py-3">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950">
                {evidence.map((ev) => (
                  <tr key={ev.id} className="hover:bg-gray-900/50">
                    <td className="px-4 py-3">
                      <span className={`rounded border px-1.5 py-0.5 text-xs ${domainColor(ev.source_domain)}`}>
                        {domainLabel(ev.source_domain)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-xs text-gray-400">{ev.source_entity_type}</div>
                      <div className="font-mono text-xs text-gray-300">{ev.source_entity_id}</div>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-300">{ev.event_type}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${severityColor(ev.severity)}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-medium ${
                        ev.observability === "OBSERVED" ? "text-green-400" :
                        ev.observability === "INFERRED" ? "text-yellow-400" : "text-gray-400"
                      }`}>
                        {ev.observability}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">{formatTs(ev.observed_at)}</td>
                    <td className="px-4 py-3 max-w-xs">
                      <div className="truncate text-xs text-gray-400" title={ev.correlation_reason}>
                        {ev.correlation_reason}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Resolve modal */}
      {resolveOpen && (
        <FormModal title="Resolve Investigation" onClose={closeResolveModal}>
          <form onSubmit={handleResolve} noValidate>
            <div className="space-y-4">
              <FormField label="Resolution reason" required>
                <select
                  value={resolveReason}
                  onChange={(e) => setResolveReason(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:outline-none"
                >
                  {RESOLUTION_REASONS.map((r) => (
                    <option key={r} value={r}>{r.replace(/_/g, " ")}</option>
                  ))}
                </select>
              </FormField>
              <FormField label="Notes">
                <textarea
                  value={resolveNotes}
                  onChange={(e) => setResolveNotes(e.target.value)}
                  rows={3}
                  maxLength={2000}
                  placeholder="Additional context for the resolution…"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none"
                />
              </FormField>
            </div>
            {resolveError && (
              <p role="alert" className="mt-3 text-sm text-red-400">
                {resolveError}
              </p>
            )}
            <div className="mt-4 flex justify-end gap-3">
              <button
                type="button"
                onClick={closeResolveModal}
                className="rounded border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actioning}
                className="rounded border border-green-700 bg-green-900/30 px-4 py-2 text-sm font-medium text-green-300 hover:bg-green-900/50 disabled:opacity-50"
              >
                {actioning ? "Resolving…" : "Resolve Case"}
              </button>
            </div>
          </form>
        </FormModal>
      )}
    </div>
  );
}

function MetaCard({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="mb-2 text-xs font-medium uppercase tracking-wider text-gray-500">{label}</div>
      {children}
    </div>
  );
}
