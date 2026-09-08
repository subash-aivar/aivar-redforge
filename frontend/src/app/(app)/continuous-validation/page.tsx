"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Target } from "@/lib/types";
import { InvestigationDrawer } from "@/components/cc";
import {
  activatePolicy,
  createPolicy,
  disablePolicy,
  getChangeFeed,
  getPolicy,
  listPolicies,
  listPolicyDrift,
  pausePolicy,
  resumePolicy,
  runPolicyNow,
  type ContinuousValidationPolicy,
  type SecurityDriftEvent,
} from "@/lib/continuousValidation";
import {
  cadenceLabel,
  displayEnum,
  driftCategoryBadgeClass,
  driftCategoryLabel,
  formatDateTime,
  lifecycleBadgeClass,
  lifecycleLabel,
  POLICY_LIFECYCLES,
  toCanonicalLifecycle,
  VALIDATION_CADENCES,
  VALIDATION_PROFILES,
} from "./continuous-validation-helpers";

function CreatePolicyForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (p: ContinuousValidationPolicy) => void;
}) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState("");
  const [profile, setProfile] = useState<string>(VALIDATION_PROFILES[0]);
  const [cadence, setCadence] = useState<string>(VALIDATION_CADENCES[2]);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    api
      .get<Target[]>("/api/v1/targets")
      .then((data) => setTargets(Array.isArray(data) ? data : []))
      .catch(() => setTargets([]));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    if (!targetId) {
      setFormError("Select a canonical target.");
      return;
    }
    setSubmitting(true);
    try {
      const created = await createPolicy({
        target_id: targetId,
        profile,
        cadence: cadence as ContinuousValidationPolicy["cadence"],
      });
      onCreated(created);
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to create policy.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-5"
    >
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">New Continuous Validation Policy</h2>
        <button type="button" onClick={onClose} className="text-gray-500 hover:text-gray-300">
          ✕
        </button>
      </div>

      {formError ? (
        <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {formError}
        </div>
      ) : null}

      <div className="mt-4">
        <div className="text-xs uppercase tracking-wide text-gray-500">Canonical target</div>
        <select
          value={targetId}
          onChange={(e) => setTargetId(e.target.value)}
          className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300"
        >
          <option value="">Select a registered AI target…</option>
          {targets.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} — {t.endpoint}
            </option>
          ))}
        </select>
      </div>

      <div className="mt-4">
        <div className="text-xs uppercase tracking-wide text-gray-500">Validation profile</div>
        <select
          value={profile}
          onChange={(e) => setProfile(e.target.value)}
          className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300"
        >
          {VALIDATION_PROFILES.map((p) => (
            <option key={p} value={p}>
              {displayEnum(p)}
            </option>
          ))}
        </select>
      </div>

      <div className="mt-4">
        <div className="text-xs uppercase tracking-wide text-gray-500">Cadence</div>
        <select
          value={cadence}
          onChange={(e) => setCadence(e.target.value)}
          className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300"
        >
          {VALIDATION_CADENCES.map((c) => (
            <option key={c} value={c}>
              {cadenceLabel(c)}
            </option>
          ))}
        </select>
        <div className="mt-1 text-xs text-gray-600">
          One of four closed, server-controlled cadences. No cron expression or free-text
          schedule can ever be submitted.
        </div>
      </div>

      <div className="mt-5 flex justify-end gap-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
        >
          {submitting ? "Creating…" : "Create Policy"}
        </button>
      </div>
    </form>
  );
}

function DriftEventRow({ event }: { event: SecurityDriftEvent }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded border px-2 py-0.5 font-medium ${driftCategoryBadgeClass(event.category)}`}
        >
          {driftCategoryLabel(event.category)}
        </span>
        <span className="text-gray-500">{event.identity_key}</span>
      </div>
      <div className="mt-1 text-gray-400">{event.summary}</div>
      <div className="mt-1 text-gray-600">Detected {formatDateTime(event.detected_at)}</div>
    </div>
  );
}

function PolicyDetail({
  policyId,
  onClose,
  onChanged,
}: {
  policyId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [policy, setPolicy] = useState<ContinuousValidationPolicy | null>(null);
  const [drift, setDrift] = useState<SecurityDriftEvent[] | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [runResult, setRunResult] = useState<string>("");

  const refresh = useCallback(() => {
    getPolicy(policyId)
      .then(setPolicy)
      .catch(() => setError("UNAVAILABLE — failed to load policy."));
    listPolicyDrift(policyId, { limit: 50 })
      .then(setDrift)
      .catch(() => setError("UNAVAILABLE — failed to load drift feed."));
  }, [policyId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleAction(action: () => Promise<ContinuousValidationPolicy>) {
    setActionError("");
    setActionBusy(true);
    try {
      const updated = await action();
      setPolicy(updated);
      onChanged();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Action failed.");
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRunNow() {
    setActionError("");
    setRunResult("");
    setActionBusy(true);
    try {
      const result = await runPolicyNow(policyId);
      setRunResult(`Execution ${result.execution_id} — ${displayEnum(result.status)}`);
      refresh();
      onChanged();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Run Now failed.");
    } finally {
      setActionBusy(false);
    }
  }

  const lifecycle = policy?.lifecycle;

  return (
    <InvestigationDrawer
      open
      onClose={onClose}
      title="Continuous Validation Policy"
      entityId={policyId}
      fields={
        policy
          ? [
              ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
              ...(actionError
                ? [{ label: "Action Error", value: <span className="text-red-400">{actionError}</span> }]
                : []),
              ...(runResult
                ? [{ label: "Run Result", value: <span className="text-emerald-400">{runResult}</span> }]
                : []),
              {
                label: "Lifecycle",
                value: (
                  <span
                    className={`rounded border px-2 py-0.5 text-xs font-medium ${lifecycleBadgeClass(policy.lifecycle)}`}
                  >
                    {displayEnum(toCanonicalLifecycle(policy.lifecycle))}
                  </span>
                ),
              },
              { label: "Target", value: policy.target_id },
              {
                label: "Profile",
                value: `${displayEnum(policy.profile)} · Cadence: ${displayEnum(policy.cadence)}`,
              },
              {
                label: "Schedule",
                value: `Next due: ${formatDateTime(policy.next_due_at)} · Last scheduled: ${formatDateTime(policy.last_scheduled_at)}`,
              },
              {
                label: "Actions",
                value:
                  lifecycle === "disabled" ? (
                    <div className="text-xs text-gray-600">
                      Disabled policies are terminal — create a new policy to resume continuous
                      validation for this target.
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {lifecycle === "draft" ? (
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={() => handleAction(() => activatePolicy(policyId))}
                          className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                        >
                          Activate
                        </button>
                      ) : null}
                      {lifecycle === "active" ? (
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={() => handleAction(() => pausePolicy(policyId))}
                          className="rounded-lg border border-amber-700 px-3 py-1.5 text-xs text-amber-400 hover:bg-amber-950 disabled:opacity-50"
                        >
                          Pause
                        </button>
                      ) : null}
                      {lifecycle === "paused" ? (
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={() => handleAction(() => resumePolicy(policyId))}
                          className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                        >
                          Resume
                        </button>
                      ) : null}
                      <button
                        type="button"
                        disabled={actionBusy}
                        onClick={() => handleAction(() => disablePolicy(policyId))}
                        className="rounded-lg border border-red-700 px-3 py-1.5 text-xs text-red-400 hover:bg-red-950 disabled:opacity-50"
                      >
                        Disable
                      </button>
                      <button
                        type="button"
                        disabled={actionBusy}
                        onClick={handleRunNow}
                        className="rounded-lg border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-gray-600 disabled:opacity-50"
                      >
                        Run Now
                      </button>
                    </div>
                  ),
              },
              {
                label: `Security Drift (${drift?.length ?? 0})`,
                value:
                  drift === null ? (
                    <span className="text-gray-500">Loading drift feed…</span>
                  ) : drift.length === 0 ? (
                    <span className="text-gray-500">No drift detected yet for this policy.</span>
                  ) : (
                    <div className="space-y-2">
                      {drift.map((d) => (
                        <DriftEventRow key={d.id} event={d} />
                      ))}
                    </div>
                  ),
              },
            ]
          : [
              ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
              { label: "Status", value: <span className="text-gray-400">Loading policy…</span> },
            ]
      }
    />
  );
}

export default function ContinuousValidationPage() {
  const [policies, setPolicies] = useState<ContinuousValidationPolicy[] | null>(null);
  const [changeFeed, setChangeFeed] = useState<SecurityDriftEvent[] | null>(null);
  const [lifecycleFilter, setLifecycleFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setError("");
    listPolicies({
      lifecycle: (lifecycleFilter || undefined) as ContinuousValidationPolicy["lifecycle"] | undefined,
    })
      .then(setPolicies)
      .catch(() => setError("UNAVAILABLE — failed to load continuous validation policies."));
    getChangeFeed({ limit: 50 })
      .then(setChangeFeed)
      .catch(() => setError("UNAVAILABLE — failed to load the security drift change feed."));
  }, [lifecycleFilter]);

  useEffect(() => {
    load();
  }, [load]);

  function handleCreated(p: ContinuousValidationPolicy) {
    setShowCreate(false);
    setPolicies((prev) => (prev ? [p, ...prev] : [p]));
    setSelectedId(p.id);
    load();
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Continuous Validation</h1>
          <p className="mt-1 text-sm text-gray-400">
            Scheduled, server-controlled revalidation of authorized canonical targets — a fresh
            authorization check on every run, deterministic security drift, and reactivated
            conditions reuse the same canonical identity. No cron expressions, no client-owned
            scheduling truth.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
        >
          New Policy
        </button>
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {showCreate ? (
        <CreatePolicyForm onClose={() => setShowCreate(false)} onCreated={handleCreated} />
      ) : null}

      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={lifecycleFilter}
          onChange={(e) => setLifecycleFilter(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All lifecycle states</option>
          {POLICY_LIFECYCLES.map((l) => (
            <option key={l} value={l}>
              {lifecycleLabel(l)}
            </option>
          ))}
        </select>
      </div>

      {policies === null ? (
        <div className="mt-6 text-gray-400">Loading policies…</div>
      ) : policies.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No continuous validation policies match the current filter.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {policies.map((p) => (
            <button
              key={p.id}
              onClick={() => setSelectedId(p.id)}
              className="block w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-700"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded border px-2 py-0.5 text-xs font-medium ${lifecycleBadgeClass(p.lifecycle)}`}
                >
                  {displayEnum(toCanonicalLifecycle(p.lifecycle))}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {displayEnum(p.profile)}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {displayEnum(p.cadence)}
                </span>
              </div>
              <div className="mt-2 text-xs text-gray-500">
                Target {p.target_id} · Next due {formatDateTime(p.next_due_at)}
              </div>
            </button>
          ))}
        </div>
      )}

      <div className="mt-10 border-t border-gray-800 pt-6">
        <h2 className="text-lg font-semibold text-white">Security Drift Change Feed</h2>
        <p className="mt-1 text-sm text-gray-400">
          Every detected canonical-state change, across every policy, newest first.
        </p>
        {changeFeed === null ? (
          <div className="mt-4 text-gray-400">Loading change feed…</div>
        ) : changeFeed.length === 0 ? (
          <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
            No drift has been detected yet.
          </div>
        ) : (
          <div className="mt-4 space-y-2">
            {changeFeed.map((d) => (
              <DriftEventRow key={d.id} event={d} />
            ))}
          </div>
        )}
      </div>

      {selectedId ? (
        <PolicyDetail policyId={selectedId} onClose={() => setSelectedId(null)} onChanged={load} />
      ) : null}
    </div>
  );
}
