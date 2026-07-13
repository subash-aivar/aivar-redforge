"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Target } from "@/lib/types";
import {
  cancelExecution,
  createExecution,
  getExecution,
  getExecutionResult,
  getExecutionSummary,
  listExecutionEvents,
  listExecutions,
  type ExecutionEvent,
  type ValidationExecution,
  type ValidationExecutionSummary,
  type ValidationResult,
} from "@/lib/validationOperations";
import {
  displayEnum,
  eventTypeLabel,
  formatDateTime,
  protocolValidationStateBadgeClass,
  protocolValidationStateLabel,
  serviceStateLabel,
  statusBadgeClass,
  stepSourceBadgeClass,
  stepSourceLabel,
  stepStatusBadgeClass,
  stepTypeLabel,
  toCanonicalStatus,
  VALIDATION_PROFILES,
} from "./validation-operations-helpers";

const STATUS_LABELS: Record<string, string> = {
  pending: "Pending",
  policy_checking: "Policy Checking",
  authorized: "Authorized",
  running: "Running",
  completed: "Completed",
  partially_completed: "Partial",
  failed: "Failed",
  cancelled: "Cancelled",
  denied: "Denied",
};

const NON_TERMINAL_STATUSES = new Set([
  "pending",
  "policy_checking",
  "authorized",
  "running",
]);

function SummaryCard({ label, count }: { label: string; count: number }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-2xl font-bold text-white">{count}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

function stepProgress(execution: ValidationExecution): string {
  if (execution.steps.length === 0) return "no steps";
  const completed = execution.steps.filter((s) => s.status === "completed").length;
  return `${completed}/${execution.steps.length} steps completed`;
}

function StartValidationForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (e: ValidationExecution) => void;
}) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState("");
  const [profile, setProfile] = useState<string>(VALIDATION_PROFILES[0]);
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
      const created = await createExecution({ target_id: targetId, profile });
      onCreated(created);
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to start validation.");
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
        <h2 className="text-sm font-semibold text-white">Start Validation</h2>
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
        {targets.length === 0 ? (
          <div className="mt-1 text-xs text-gray-600">
            No AI targets registered yet — register one under Targets first.
          </div>
        ) : null}
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
        <div className="mt-1 text-xs text-gray-600">
          One of two closed, server-controlled profiles. No arbitrary steps, ports, adaptive
          rules, or scan commands can be submitted.
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
          {submitting ? "Starting…" : "Start Validation"}
        </button>
      </div>
    </form>
  );
}

function ExecutionDetail({
  executionId,
  onClose,
  onChanged,
}: {
  executionId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [execution, setExecution] = useState<ValidationExecution | null>(null);
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);

  const refresh = useCallback(() => {
    getExecution(executionId)
      .then(setExecution)
      .catch(() => setError("UNAVAILABLE — failed to load execution."));
    listExecutionEvents(executionId, 0, 500)
      .then(setEvents)
      .catch(() => setError("UNAVAILABLE — failed to load execution events."));
    getExecutionResult(executionId)
      .then(setResult)
      .catch(() => setResult(null));
  }, [executionId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Live polling: only while the execution is still non-terminal.
  useEffect(() => {
    if (!execution || !NON_TERMINAL_STATUSES.has(execution.status)) return;
    const intervalId = setInterval(refresh, 2000);
    return () => clearInterval(intervalId);
  }, [execution, refresh]);

  async function handleCancel() {
    setActionError("");
    setActionBusy(true);
    try {
      const updated = await cancelExecution(executionId);
      setExecution(updated);
      onChanged();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Cancellation failed.");
    } finally {
      setActionBusy(false);
    }
  }

  const canCancel = execution != null && NON_TERMINAL_STATUSES.has(execution.status);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-6">
        <div className="flex items-start justify-between">
          <h2 className="text-lg font-semibold text-white">Validation Execution {executionId}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            ✕
          </button>
        </div>

        {error ? (
          <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        ) : null}
        {actionError ? (
          <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
            {actionError}
          </div>
        ) : null}

        {execution ? (
          <>
            <div className="mt-4 space-y-2 text-sm">
              <div>
                <span className="text-gray-500">Status: </span>
                <span
                  className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(execution.status)}`}
                >
                  {displayEnum(toCanonicalStatus(execution.status))}
                </span>
                {NON_TERMINAL_STATUSES.has(execution.status) ? (
                  <span className="ml-2 text-xs text-gray-500">Live — refreshing…</span>
                ) : null}
              </div>
              <div>
                <span className="text-gray-500">Target: </span>
                <span className="text-gray-300">{execution.target_id}</span>
              </div>
              <div>
                <span className="text-gray-500">Profile: </span>
                <span className="text-gray-300">{displayEnum(execution.profile)}</span>
              </div>
              {execution.policy_reason_code ? (
                <div>
                  <span className="text-gray-500">Policy reason: </span>
                  <span className="text-gray-300">{execution.policy_reason_code}</span>
                </div>
              ) : null}
              {execution.failure_reason ? (
                <div>
                  <span className="text-gray-500">Failure reason: </span>
                  <span className="text-gray-300">{execution.failure_reason}</span>
                </div>
              ) : null}
              <div>
                <span className="text-gray-500">Created: </span>
                <span className="text-gray-300">{formatDateTime(execution.created_at)}</span>
                <span className="text-gray-500"> · Started: </span>
                <span className="text-gray-300">{formatDateTime(execution.started_at)}</span>
                <span className="text-gray-500"> · Completed: </span>
                <span className="text-gray-300">{formatDateTime(execution.completed_at)}</span>
              </div>
            </div>

            {execution.plan_summary ? (
              <div className="mt-4 border-t border-gray-800 pt-4">
                <div className="text-xs uppercase tracking-wide text-gray-500">Plan</div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-400">
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.initial_step_count} initial step
                    {execution.plan_summary.initial_step_count === 1 ? "" : "s"}
                  </span>
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.adaptive_step_count} adaptive step
                    {execution.plan_summary.adaptive_step_count === 1 ? "" : "s"}
                  </span>
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.discovered_address_count} discovered address
                    {execution.plan_summary.discovered_address_count === 1 ? "" : "es"}
                  </span>
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.reachable_port_count} reachable port
                    {execution.plan_summary.reachable_port_count === 1 ? "" : "s"}
                  </span>
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.validated_service_count} validated service
                    {execution.plan_summary.validated_service_count === 1 ? "" : "s"}
                  </span>
                  <span className="rounded bg-gray-800 px-2 py-0.5">
                    {execution.plan_summary.condition_count} condition
                    {execution.plan_summary.condition_count === 1 ? "" : "s"}
                  </span>
                </div>
              </div>
            ) : null}

            <div className="mt-4 border-t border-gray-800 pt-4">
              <div className="text-xs uppercase tracking-wide text-gray-500">Steps</div>
              {execution.steps.length === 0 ? (
                <div className="mt-2 text-sm text-gray-500">
                  No steps were ever created for this execution.
                </div>
              ) : (
                <div className="mt-2 space-y-2">
                  {execution.steps.map((step) => (
                    <div
                      key={step.id}
                      className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-gray-300">
                          {stepTypeLabel(step.step_type)}
                        </span>
                        <span
                          className={`rounded border px-2 py-0.5 ${stepStatusBadgeClass(step.status)}`}
                        >
                          {displayEnum(step.status)}
                        </span>
                        <span
                          className={`rounded border px-2 py-0.5 ${stepSourceBadgeClass(step.source)}`}
                        >
                          {stepSourceLabel(step.source)}
                        </span>
                        {step.protocol_validation_state ? (
                          <span
                            className={`rounded border px-2 py-0.5 ${protocolValidationStateBadgeClass(step.protocol_validation_state)}`}
                          >
                            {protocolValidationStateLabel(step.protocol_validation_state)}
                          </span>
                        ) : null}
                        {step.error_category ? (
                          <span className="text-gray-500">{step.error_category}</span>
                        ) : null}
                      </div>
                      {step.source === "adaptive" ? (
                        <div className="mt-1 text-gray-600">
                          Rule {step.adaptive_rule_id} v{step.adaptive_rule_version} — triggered by{" "}
                          {step.source_fact_ref}
                        </div>
                      ) : null}
                      {step.validator_id ? (
                        <div className="mt-1 text-gray-600">
                          Validator: {step.validator_id} v{step.validator_version}
                        </div>
                      ) : null}
                      {step.evidence.length > 0 ? (
                        <div className="mt-2 space-y-0.5 text-gray-500">
                          {step.evidence.map((e, i) => (
                            <div key={i}>
                              {e.label}: <span className="text-gray-400">{e.value}</span>
                            </div>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-4 border-t border-gray-800 pt-4">
              <div className="text-xs uppercase tracking-wide text-gray-500">Event timeline</div>
              {events.length === 0 ? (
                <div className="mt-2 text-sm text-gray-500">No events recorded yet.</div>
              ) : (
                <div className="mt-2 space-y-1">
                  {events.map((ev) => (
                    <div key={ev.id} className="text-xs text-gray-500">
                      <span className="text-gray-600">#{ev.sequence}</span>{" "}
                      <span className="text-gray-300">{eventTypeLabel(ev.event_type)}</span>{" "}
                      <span>{formatDateTime(ev.occurred_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {result ? (
              <div className="mt-4 border-t border-gray-800 pt-4">
                <div className="text-xs uppercase tracking-wide text-gray-500">
                  Crisp result — structured facts only
                </div>
                <div className="mt-2 space-y-1 text-sm text-gray-300">
                  <div>
                    TCP reachable:{" "}
                    {result.tcp_reachable === null ? "UNKNOWN" : result.tcp_reachable ? "yes" : "no"}
                  </div>
                  <div>
                    Application-layer validated:{" "}
                    {result.application_layer_validated === null
                      ? "UNKNOWN"
                      : result.application_layer_validated
                        ? "yes"
                        : "no"}
                  </div>
                  <div>Validation basis: {result.validation_basis || "UNKNOWN"}</div>
                  {result.tls_protocol_version ? (
                    <div>TLS protocol: {result.tls_protocol_version}</div>
                  ) : null}
                  {result.http_status_code ? (
                    <div>HTTP status: {result.http_status_code}</div>
                  ) : null}
                  <div>
                    Conditions observed:{" "}
                    {result.conditions_observed.length > 0
                      ? result.conditions_observed.join(", ")
                      : "none"}
                  </div>
                  {result.failed_steps.length > 0 ? (
                    <div>Failed steps: {result.failed_steps.map(stepTypeLabel).join(", ")}</div>
                  ) : null}
                  {result.discovered_addresses.length > 0 ? (
                    <div>Discovered addresses: {result.discovered_addresses.join(", ")}</div>
                  ) : null}
                  {result.reachable_ports.length > 0 ? (
                    <div>Reachable ports: {result.reachable_ports.join(", ")}</div>
                  ) : null}
                  {result.validated_services.length > 0 ? (
                    <div>
                      <div className="text-gray-500">Services:</div>
                      <div className="mt-1 space-y-1">
                        {result.validated_services.map((svc) => (
                          <div key={svc.port} className="flex flex-wrap items-center gap-2 text-xs">
                            <span className="text-gray-400">
                              {svc.port}/tcp reachable — {svc.hint}
                            </span>
                            <span
                              className={`rounded border px-2 py-0.5 ${
                                svc.state === "validated"
                                  ? "border-emerald-800 bg-emerald-950 text-emerald-400"
                                  : "border-gray-700 bg-gray-800 text-gray-400"
                              }`}
                            >
                              {serviceStateLabel(svc.state)}
                            </span>
                            {svc.validator_id ? (
                              <span className="text-gray-600">
                                via {svc.validator_id} v{svc.validator_version}
                              </span>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {result.correlations_created !== null ? (
                    <div>
                      Correlations — created {result.correlations_created}, updated{" "}
                      {result.correlations_updated}, resolved {result.correlations_resolved}
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}
          </>
        ) : (
          <div className="mt-6 text-gray-400">Loading execution…</div>
        )}

        <div className="mt-6 flex flex-wrap justify-end gap-3">
          {canCancel ? (
            <button
              disabled={actionBusy}
              onClick={handleCancel}
              className="rounded-lg border border-red-700 px-4 py-2 text-sm text-red-400 hover:bg-red-950 disabled:opacity-50"
            >
              Cancel Execution
            </button>
          ) : null}
          <button
            onClick={onClose}
            className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ValidationOperationsPage() {
  const [summary, setSummary] = useState<ValidationExecutionSummary | null>(null);
  const [executions, setExecutions] = useState<ValidationExecution[] | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setError("");
    getExecutionSummary()
      .then(setSummary)
      .catch(() => setError("UNAVAILABLE — failed to load validation overview."));
    listExecutions({ status: statusFilter || undefined })
      .then(setExecutions)
      .catch(() => setError("UNAVAILABLE — failed to load validation executions."));
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load]);

  function handleCreated(e: ValidationExecution) {
    setShowCreate(false);
    setExecutions((prev) => (prev ? [e, ...prev] : [e]));
    setSelectedId(e.id);
    load();
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Validation Operations</h1>
          <p className="mt-1 text-sm text-gray-400">
            Gated, authorized, bounded, non-destructive active validation — real DNS/TCP/TLS/HTTP
            observation against explicitly authorized canonical targets only. No exploit
            execution, no arbitrary scanning.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
        >
          Start Validation
        </button>
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : null}

      {summary ? (
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {Object.keys(STATUS_LABELS).map((status) => (
            <SummaryCard
              key={status}
              label={STATUS_LABELS[status]}
              count={summary[status as keyof ValidationExecutionSummary] ?? 0}
            />
          ))}
        </div>
      ) : (
        <div className="mt-6 text-gray-400">Loading overview…</div>
      )}

      {showCreate ? (
        <StartValidationForm onClose={() => setShowCreate(false)} onCreated={handleCreated} />
      ) : null}

      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
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

      {executions === null ? (
        <div className="mt-6 text-gray-400">Loading executions…</div>
      ) : executions.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No validation executions match the current filter.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {executions.map((e) => (
            <button
              key={e.id}
              onClick={() => setSelectedId(e.id)}
              className="block w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-700"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(e.status)}`}
                >
                  {displayEnum(toCanonicalStatus(e.status))}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {displayEnum(e.profile)}
                </span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {stepProgress(e)}
                </span>
              </div>
              <div className="mt-2 text-xs text-gray-500">
                Target {e.target_id} · Started {formatDateTime(e.started_at)} · Completed{" "}
                {formatDateTime(e.completed_at)}
              </div>
            </button>
          ))}
        </div>
      )}

      {selectedId ? (
        <ExecutionDetail
          executionId={selectedId}
          onClose={() => setSelectedId(null)}
          onChanged={load}
        />
      ) : null}
    </div>
  );
}
