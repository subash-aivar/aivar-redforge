"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { FormField, FormModal } from "@/components/cc";
import {
  approveAuthorization,
  createAuthorization,
  getAuthorizationSummary,
  listAuthorizations,
  listDecisions,
  rejectAuthorization,
  revokeAuthorization,
  submitAuthorization,
  type Authorization,
  type AuthorizationSummary,
  type DecisionHistoryEntry,
  type ScopeEntry,
} from "@/lib/authorizations";
import { getMe } from "@/lib/auth";
import {
  decisionBadgeClass,
  displayEnum,
  formatDateTime,
  REQUESTABLE_ACTION_CLASSES,
  SCOPE_ENTITY_TYPES,
  statusBadgeClass,
  toCanonicalStatus,
} from "./authorization-helpers";

const STATUS_LABELS: Record<string, string> = {
  draft: "Draft",
  pending_approval: "Pending Approval",
  active: "Active",
  rejected: "Rejected",
  revoked: "Revoked",
  expired: "Expired",
};

function SummaryCard({ label, count }: { label: string; count: number }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-2xl font-bold text-white">{count}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

function CreateAuthorizationForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (a: Authorization) => void;
}) {
  const [actionClasses, setActionClasses] = useState<Set<string>>(new Set());
  const [scope, setScope] = useState<ScopeEntry[]>([
    { entity_type: "ai_target", entity_id: "" },
  ]);
  const [validFrom, setValidFrom] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");
  const firstActionClassRef = useRef<HTMLInputElement>(null);
  const firstScopeEntityIdRef = useRef<HTMLInputElement>(null);
  const validFromRef = useRef<HTMLInputElement>(null);
  const validUntilRef = useRef<HTMLInputElement>(null);

  function toggleActionClass(ac: string) {
    setActionClasses((prev) => {
      const next = new Set(prev);
      if (next.has(ac)) next.delete(ac);
      else next.add(ac);
      return next;
    });
  }

  function updateScopeEntry(index: number, patch: Partial<ScopeEntry>) {
    setScope((prev) => prev.map((s, i) => (i === index ? { ...s, ...patch } : s)));
  }

  function addScopeEntry() {
    setScope((prev) => [...prev, { entity_type: "ai_target", entity_id: "" }]);
  }

  function removeScopeEntry(index: number) {
    setScope((prev) => prev.filter((_, i) => i !== index));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    if (actionClasses.size === 0) {
      setFormError("Select at least one action class.");
      firstActionClassRef.current?.focus();
      return;
    }
    const cleanScope = scope.filter((s) => s.entity_id.trim() !== "");
    if (cleanScope.length === 0) {
      setFormError("Add at least one scope entity.");
      firstScopeEntityIdRef.current?.focus();
      return;
    }
    if (!validFrom || !validUntil) {
      setFormError("Set both a valid-from and valid-until time.");
      (!validFrom ? validFromRef : validUntilRef).current?.focus();
      return;
    }
    setSubmitting(true);
    try {
      const created = await createAuthorization({
        action_classes: Array.from(actionClasses),
        scope: cleanScope,
        valid_from: new Date(validFrom).toISOString(),
        valid_until: new Date(validUntil).toISOString(),
      });
      onCreated(created);
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to create authorization.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-5"
      noValidate
    >
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">New Authorization (DRAFT)</h2>
        <button
          type="button"
          onClick={onClose}
          className="text-gray-500 hover:text-gray-300"
        >
          ✕
        </button>
      </div>

      {formError ? (
        <div role="alert" className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {formError}
        </div>
      ) : null}

      <fieldset className="mt-4">
        <legend className="text-xs uppercase tracking-wide text-gray-500">Action classes</legend>
        <div className="mt-2 flex flex-wrap gap-2">
          {REQUESTABLE_ACTION_CLASSES.map((ac, i) => (
            <label
              key={ac}
              className={`cursor-pointer rounded-lg border px-3 py-1.5 text-xs ${
                actionClasses.has(ac)
                  ? "border-red-700 bg-red-950 text-red-300"
                  : "border-gray-700 bg-gray-800 text-gray-400"
              }`}
            >
              <input
                ref={i === 0 ? firstActionClassRef : undefined}
                type="checkbox"
                className="mr-1.5"
                checked={actionClasses.has(ac)}
                onChange={() => toggleActionClass(ac)}
              />
              {displayEnum(ac)}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="mt-4">
        <legend className="text-xs uppercase tracking-wide text-gray-500">Scope</legend>
        <div className="mt-2 space-y-2">
          {scope.map((entry, i) => (
            <div key={i} className="flex gap-2">
              <FormField label={`Scope entity type ${i + 1}`}>
                <select
                  value={entry.entity_type}
                  onChange={(e) => updateScopeEntry(i, { entity_type: e.target.value })}
                  className="rounded-lg border border-gray-700 bg-gray-800 px-2 py-1.5 text-xs text-gray-300"
                >
                  {SCOPE_ENTITY_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </FormField>
              <div className="flex-1">
                <FormField label={`Scope entity ID ${i + 1}`}>
                  <input
                    ref={i === 0 ? firstScopeEntityIdRef : undefined}
                    type="text"
                    placeholder="Canonical entity ID"
                    value={entry.entity_id}
                    onChange={(e) => updateScopeEntry(i, { entity_id: e.target.value })}
                    className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-white placeholder-gray-500"
                  />
                </FormField>
              </div>
              {scope.length > 1 ? (
                <button
                  type="button"
                  onClick={() => removeScopeEntry(i)}
                  aria-label={`Remove scope entity ${i + 1}`}
                  className="self-start pt-6 text-gray-500 hover:text-red-400"
                >
                  ✕
                </button>
              ) : null}
            </div>
          ))}
          <button
            type="button"
            onClick={addScopeEntry}
            className="text-xs text-gray-400 hover:text-gray-200"
          >
            + Add scope entity
          </button>
        </div>
      </fieldset>

      <div className="mt-4 grid grid-cols-2 gap-3">
        <FormField label="Valid from" required>
          <input
            ref={validFromRef}
            type="datetime-local"
            value={validFrom}
            onChange={(e) => setValidFrom(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-white"
          />
        </FormField>
        <FormField label="Valid until" required>
          <input
            ref={validUntilRef}
            type="datetime-local"
            value={validUntil}
            onChange={(e) => setValidUntil(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-white"
          />
        </FormField>
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
          {submitting ? "Creating…" : "Create Draft"}
        </button>
      </div>
    </form>
  );
}

export default function AuthorizationPage() {
  const [summary, setSummary] = useState<AuthorizationSummary | null>(null);
  const [authorizations, setAuthorizations] = useState<Authorization[] | null>(null);
  const [decisions, setDecisions] = useState<DecisionHistoryEntry[] | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [tab, setTab] = useState<"authorizations" | "decisions">("authorizations");
  const [selected, setSelected] = useState<Authorization | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);

  const load = useCallback(() => {
    setError("");
    getAuthorizationSummary()
      .then(setSummary)
      .catch(() => setError("UNAVAILABLE — failed to load authorization overview."));
    listAuthorizations({ status: statusFilter || undefined })
      .then(setAuthorizations)
      .catch(() => setError("UNAVAILABLE — failed to load authorizations."));
    listDecisions({ limit: 100 })
      .then(setDecisions)
      .catch(() => setError("UNAVAILABLE — failed to load policy decision history."));
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    getMe()
      .then((u) => setCurrentUserId(u.user_id))
      .catch(() => setCurrentUserId(null));
  }, []);

  function handleCreated(a: Authorization) {
    setShowCreate(false);
    setAuthorizations((prev) => (prev ? [a, ...prev] : [a]));
    load();
  }

  async function withAction(fn: () => Promise<Authorization>) {
    setActionError("");
    setActionBusy(true);
    try {
      const updated = await fn();
      setSelected(updated);
      load();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Action failed.");
    } finally {
      setActionBusy(false);
    }
  }

  const selectedDecisions = selected
    ? (decisions ?? []).filter((d) => d.authorization_id === selected.id)
    : [];
  const isOwnRequest = selected != null && currentUserId != null && selected.requester_user_id === currentUserId;

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">Authorization &amp; Execution Policy</h1>
          <p className="mt-1 text-sm text-gray-400">
            The control plane that decides ALLOW, DENY, or APPROVAL_REQUIRED for
            future active security-testing actions. No action is executed here —
            this only governs whether one would be permitted.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="shrink-0 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
        >
          New Authorization
        </button>
      </div>

      {error ? (
        <div role="alert" className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {Object.keys(STATUS_LABELS).map((status) => (
            <SummaryCard
              key={status}
              label={STATUS_LABELS[status]}
              count={summary[status as keyof AuthorizationSummary] ?? 0}
            />
          ))}
        </div>
      ) : (
        <div className="mt-6 text-gray-400">Loading overview…</div>
      )}

      {showCreate ? (
        <CreateAuthorizationForm onClose={() => setShowCreate(false)} onCreated={handleCreated} />
      ) : null}

      <div className="mt-6 flex gap-2 border-b border-gray-800">
        <button
          onClick={() => setTab("authorizations")}
          className={`px-3 py-2 text-sm font-medium ${
            tab === "authorizations"
              ? "border-b-2 border-red-500 text-white"
              : "text-gray-500 hover:text-gray-300"
          }`}
        >
          Authorizations
        </button>
        <button
          onClick={() => setTab("decisions")}
          className={`px-3 py-2 text-sm font-medium ${
            tab === "decisions"
              ? "border-b-2 border-red-500 text-white"
              : "text-gray-500 hover:text-gray-300"
          }`}
        >
          Policy Decision History
        </button>
      </div>

      {tab === "authorizations" ? (
        <>
          <div className="mt-4 flex flex-wrap gap-3">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter authorizations by lifecycle state"
              className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
            >
              <option value="">All lifecycle states</option>
              {Object.entries(STATUS_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {authorizations === null ? (
            <div className="mt-6 text-gray-400">Loading authorizations…</div>
          ) : authorizations.length === 0 ? (
            <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
              No authorizations match the current filter.
            </div>
          ) : (
            <div className="mt-6 space-y-3">
              {authorizations.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSelected(a)}
                  className="block w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-700"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(a.status)}`}
                    >
                      {displayEnum(toCanonicalStatus(a.status))}
                    </span>
                    {a.action_classes.map((ac) => (
                      <span
                        key={ac}
                        className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400"
                      >
                        {displayEnum(ac)}
                      </span>
                    ))}
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                      {a.scope.length} scope {a.scope.length === 1 ? "entity" : "entities"}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-gray-500">
                    Requester {a.requester_user_id} · Valid {formatDateTime(a.valid_from)} →{" "}
                    {formatDateTime(a.valid_until)} · Updated {formatDateTime(a.updated_at)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </>
      ) : (
        <div className="mt-6">
          {decisions === null ? (
            <div className="text-gray-400">Loading decision history…</div>
          ) : decisions.length === 0 ? (
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
              No policy decisions recorded yet.
            </div>
          ) : (
            <div className="space-y-2">
              {decisions.map((d) => (
                <div
                  key={d.id}
                  className="rounded-xl border border-gray-800 bg-gray-900 p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 font-medium ${decisionBadgeClass(d.decision)}`}
                    >
                      {displayEnum(d.decision)}
                    </span>
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-gray-400">
                      {d.reason_code}
                    </span>
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-gray-400">
                      {displayEnum(d.action_class ?? d.raw_action_class)}
                    </span>
                    <span className="text-gray-500">{formatDateTime(d.evaluated_at)}</span>
                  </div>
                  <div className="mt-1 text-gray-500">
                    Actor {d.actor_user_id}
                    {d.authorization_id ? ` · Authorization ${d.authorization_id}` : ""}
                    {d.entity_refs.length > 0
                      ? ` · Entities: ${d.entity_refs
                          .map((e) => `${e.entity_type}:${e.entity_id}`)
                          .join(", ")}`
                      : ""}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {selected ? (
        <FormModal
          title={`Authorization ${selected.id}`}
          hideTitle
          contentClassName="max-h-[85vh] w-full max-w-xl overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-6"
          onClose={() => {
            setSelected(null);
            setActionError("");
          }}
        >
            <div className="flex items-start justify-between">
              <h2 className="text-lg font-semibold text-white">Authorization {selected.id}</h2>
              <button
                onClick={() => {
                  setSelected(null);
                  setActionError("");
                }}
                aria-label="Close authorization detail"
                className="text-gray-500 hover:text-gray-300"
              >
                ✕
              </button>
            </div>

            {actionError ? (
              <div role="alert" className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
                {actionError}
              </div>
            ) : null}

            <div className="mt-4 space-y-2 text-sm">
              <div>
                <span className="text-gray-500">Status: </span>
                <span
                  className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(selected.status)}`}
                >
                  {displayEnum(toCanonicalStatus(selected.status))}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Requester: </span>
                <span className="text-gray-300">{selected.requester_user_id}</span>
              </div>
              <div>
                <span className="text-gray-500">Action classes: </span>
                <span className="text-gray-300">
                  {selected.action_classes.map(displayEnum).join(", ")}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Scope: </span>
                <span className="text-gray-300">
                  {selected.scope.map((s) => `${s.entity_type}:${s.entity_id}`).join(", ")}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Valid: </span>
                <span className="text-gray-300">
                  {formatDateTime(selected.valid_from)} → {formatDateTime(selected.valid_until)}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Created: </span>
                <span className="text-gray-300">{formatDateTime(selected.created_at)}</span>
              </div>

              <div className="mt-3 border-t border-gray-800 pt-3">
                <div className="text-gray-500">Approval</div>
                {selected.approval ? (
                  <div className="mt-1 space-y-1 text-gray-300">
                    <div>Decision: {displayEnum(selected.approval.decision ?? "pending")}</div>
                    <div>Requested: {formatDateTime(selected.approval.requested_at)}</div>
                    {selected.approval.approver_user_id ? (
                      <div>Approver: {selected.approval.approver_user_id}</div>
                    ) : null}
                    {selected.approval.decided_at ? (
                      <div>Decided: {formatDateTime(selected.approval.decided_at)}</div>
                    ) : null}
                    {selected.approval.reason ? (
                      <div>Reason: {selected.approval.reason}</div>
                    ) : null}
                  </div>
                ) : (
                  <div className="mt-1 text-gray-500">Not yet submitted for approval.</div>
                )}
              </div>

              <div className="mt-3 border-t border-gray-800 pt-3">
                <div className="text-gray-500">Policy decisions for this authorization</div>
                {selectedDecisions.length === 0 ? (
                  <div className="mt-1 text-gray-500">No decisions recorded yet.</div>
                ) : (
                  <div className="mt-1 space-y-1">
                    {selectedDecisions.map((d) => (
                      <div key={d.id} className="rounded bg-gray-950 px-2 py-1 text-xs text-gray-400">
                        <span className={`rounded border px-1.5 py-0.5 ${decisionBadgeClass(d.decision)}`}>
                          {displayEnum(d.decision)}
                        </span>{" "}
                        {d.reason_code} · {formatDateTime(d.evaluated_at)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="mt-6 flex flex-wrap justify-end gap-3">
              {selected.status === "draft" ? (
                <button
                  disabled={actionBusy}
                  onClick={() => withAction(() => submitAuthorization(selected.id))}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  Submit for Approval
                </button>
              ) : null}
              {selected.status === "pending_approval" ? (
                <>
                  {isOwnRequest ? (
                    <span className="self-center text-xs text-gray-500">
                      You cannot approve your own request.
                    </span>
                  ) : null}
                  <button
                    disabled={actionBusy || isOwnRequest}
                    onClick={() => withAction(() => rejectAuthorization(selected.id))}
                    className="rounded-lg border border-red-700 px-4 py-2 text-sm text-red-400 hover:bg-red-950 disabled:opacity-50"
                  >
                    Reject
                  </button>
                  <button
                    disabled={actionBusy || isOwnRequest}
                    onClick={() => withAction(() => approveAuthorization(selected.id))}
                    className="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
                  >
                    Approve
                  </button>
                </>
              ) : null}
              {selected.status === "active" ? (
                <button
                  disabled={actionBusy}
                  onClick={() => withAction(() => revokeAuthorization(selected.id))}
                  className="rounded-lg border border-red-700 px-4 py-2 text-sm text-red-400 hover:bg-red-950 disabled:opacity-50"
                >
                  Revoke
                </button>
              ) : null}
              <button
                onClick={() => {
                  setSelected(null);
                  setActionError("");
                }}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600"
              >
                Close
              </button>
            </div>
        </FormModal>
      ) : null}
    </div>
  );
}
