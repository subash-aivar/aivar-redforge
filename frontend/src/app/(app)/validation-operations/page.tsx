"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  AsyncContent,
  DataConsole,
  FormField,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
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

function kpiTone(status: string): "default" | "danger" | "warning" | "ok" {
  if (status === "failed" || status === "denied") return "danger";
  if (status === "policy_checking" || status === "partially_completed") return "warning";
  if (status === "completed") return "ok";
  return "default";
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
  const targetSelectRef = useRef<HTMLSelectElement>(null);

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
      targetSelectRef.current?.focus();
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
      className="mb-6 rounded-xl border border-gray-800 bg-gray-900/60 p-5"
      noValidate
    >
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">Start Validation</h2>
        <button type="button" onClick={onClose} className="text-gray-500 hover:text-gray-300">
          ✕
        </button>
      </div>

      {formError ? (
        <div role="alert" className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {formError}
        </div>
      ) : null}

      <div className="mt-4">
        <FormField
          label="Canonical target"
          required
          hint={
            targets.length === 0
              ? "No AI targets registered yet — register one under Targets first."
              : undefined
          }
        >
          <select
            ref={targetSelectRef}
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300"
          >
            <option value="">Select a registered AI target…</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} — {t.endpoint}
              </option>
            ))}
          </select>
        </FormField>
      </div>

      <div className="mt-4">
        <FormField
          label="Validation profile"
          required
          hint="One of two closed, server-controlled profiles. No arbitrary steps, ports, adaptive rules, or scan commands can be submitted."
        >
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300"
          >
            {VALIDATION_PROFILES.map((p) => (
              <option key={p} value={p}>
                {displayEnum(p)}
              </option>
            ))}
          </select>
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
          {submitting ? "Starting…" : "Start Validation"}
        </button>
      </div>
    </form>
  );
}

function planSummaryValue(execution: ValidationExecution) {
  const p = execution.plan_summary;
  return (
    <div className="flex flex-wrap gap-2 text-xs text-gray-400">
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.initial_step_count} initial step{p.initial_step_count === 1 ? "" : "s"}
      </span>
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.adaptive_step_count} adaptive step{p.adaptive_step_count === 1 ? "" : "s"}
      </span>
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.discovered_address_count} discovered address{p.discovered_address_count === 1 ? "" : "es"}
      </span>
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.reachable_port_count} reachable port{p.reachable_port_count === 1 ? "" : "s"}
      </span>
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.validated_service_count} validated service{p.validated_service_count === 1 ? "" : "s"}
      </span>
      <span className="rounded bg-gray-800 px-2 py-0.5">
        {p.condition_count} condition{p.condition_count === 1 ? "" : "s"}
      </span>
    </div>
  );
}

function stepsValue(execution: ValidationExecution) {
  if (execution.steps.length === 0) {
    return <span className="text-gray-500">No steps were ever created for this execution.</span>;
  }
  return (
    <div className="space-y-2">
      {execution.steps.map((step) => (
        <div key={step.id} className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-gray-300">{stepTypeLabel(step.step_type)}</span>
            <span className={`rounded border px-2 py-0.5 ${stepStatusBadgeClass(step.status)}`}>
              {displayEnum(step.status)}
            </span>
            <span className={`rounded border px-2 py-0.5 ${stepSourceBadgeClass(step.source)}`}>
              {stepSourceLabel(step.source)}
            </span>
            {step.protocol_validation_state ? (
              <span
                className={`rounded border px-2 py-0.5 ${protocolValidationStateBadgeClass(step.protocol_validation_state)}`}
              >
                {protocolValidationStateLabel(step.protocol_validation_state)}
              </span>
            ) : null}
            {step.error_category ? <span className="text-gray-500">{step.error_category}</span> : null}
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
  );
}

function eventsValue(events: ExecutionEvent[]) {
  if (events.length === 0) {
    return <span className="text-gray-500">No events recorded yet.</span>;
  }
  return (
    <div className="space-y-1">
      {events.map((ev) => (
        <div key={ev.id} className="text-xs text-gray-500">
          <span className="text-gray-600">#{ev.sequence}</span>{" "}
          <span className="text-gray-300">{eventTypeLabel(ev.event_type)}</span>{" "}
          <span>{formatDateTime(ev.occurred_at)}</span>
        </div>
      ))}
    </div>
  );
}

function resultValue(result: ValidationResult) {
  return (
    <div className="space-y-1 text-sm text-gray-300">
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
      {result.tls_protocol_version ? <div>TLS protocol: {result.tls_protocol_version}</div> : null}
      {result.http_status_code ? <div>HTTP status: {result.http_status_code}</div> : null}
      <div>
        Conditions observed:{" "}
        {result.conditions_observed.length > 0 ? result.conditions_observed.join(", ") : "none"}
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
  );
}

export default function ValidationOperationsPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const summary = useAsync<ValidationExecutionSummary>(
    () =>
      getExecutionSummary().catch(() => {
        throw new Error("UNAVAILABLE — failed to load validation overview.");
      }),
    []
  );
  const executions = useAsync<ValidationExecution[]>(
    () =>
      listExecutions({ status: statusFilter || undefined }).catch(() => {
        throw new Error("UNAVAILABLE — failed to load validation executions.");
      }),
    [statusFilter]
  );

  // Detail state for the selected execution's investigation drawer.
  const [execution, setExecution] = useState<ValidationExecution | null>(null);
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [detailError, setDetailError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);

  const refreshDetail = useCallback(() => {
    if (!selectedId) return;
    getExecution(selectedId)
      .then(setExecution)
      .catch(() => setDetailError("UNAVAILABLE — failed to load execution."));
    listExecutionEvents(selectedId, 0, 500)
      .then(setEvents)
      .catch(() => setDetailError("UNAVAILABLE — failed to load execution events."));
    getExecutionResult(selectedId)
      .then(setResult)
      .catch(() => setResult(null));
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setExecution(null);
      setEvents([]);
      setResult(null);
      setDetailError("");
      setActionError("");
      return;
    }
    refreshDetail();
  }, [selectedId, refreshDetail]);

  // Live polling: only while the execution is still non-terminal.
  useEffect(() => {
    if (!execution || !NON_TERMINAL_STATUSES.has(execution.status)) return;
    const intervalId = setInterval(refreshDetail, 2000);
    return () => clearInterval(intervalId);
  }, [execution, refreshDetail]);

  function reloadAll() {
    summary.reload();
    executions.reload();
  }

  function handleCreated(e: ValidationExecution) {
    setShowCreate(false);
    setSelectedId(e.id);
    reloadAll();
  }

  async function handleCancel() {
    if (!selectedId) return;
    setActionError("");
    setActionBusy(true);
    try {
      const updated = await cancelExecution(selectedId);
      setExecution(updated);
      reloadAll();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Cancellation failed.");
    } finally {
      setActionBusy(false);
    }
  }

  const canCancel = execution != null && NON_TERMINAL_STATUSES.has(execution.status);

  const columns: ConsoleColumn<ValidationExecution>[] = [
    {
      key: "status",
      header: "Status",
      width: "16%",
      render: (e) => (
        <span
          className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(e.status)}`}
        >
          {displayEnum(toCanonicalStatus(e.status))}
        </span>
      ),
    },
    {
      key: "profile",
      header: "Profile",
      width: "18%",
      render: (e) => <span className="text-gray-400">{displayEnum(e.profile)}</span>,
    },
    {
      key: "progress",
      header: "Steps",
      width: "16%",
      render: (e) => <span className="text-gray-400">{stepProgress(e)}</span>,
    },
    {
      key: "target",
      header: "Target",
      width: "16%",
      render: (e) => <span className="font-mono text-gray-400">{e.target_id}</span>,
    },
    {
      key: "started",
      header: "Started",
      width: "17%",
      render: (e) => <span className="text-gray-500">{formatDateTime(e.started_at)}</span>,
    },
    {
      key: "completed",
      header: "Completed",
      width: "17%",
      render: (e) => <span className="text-gray-500">{formatDateTime(e.completed_at)}</span>,
    },
  ];

  const drawerFields: DrawerField[] = execution
    ? [
        {
          label: "Status",
          value: (
            <>
              <span
                className={`rounded border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(execution.status)}`}
              >
                {displayEnum(toCanonicalStatus(execution.status))}
              </span>
              {NON_TERMINAL_STATUSES.has(execution.status) ? (
                <span className="ml-2 text-xs text-gray-500">Live — refreshing…</span>
              ) : null}
            </>
          ),
        },
        { label: "Target", value: execution.target_id },
        { label: "Profile", value: displayEnum(execution.profile) },
        ...(execution.policy_reason_code
          ? [{ label: "Policy Reason", value: execution.policy_reason_code }]
          : []),
        ...(execution.failure_reason
          ? [{ label: "Failure Reason", value: execution.failure_reason }]
          : []),
        {
          label: "Timeline",
          value: (
            <>
              Created {formatDateTime(execution.created_at)} · Started{" "}
              {formatDateTime(execution.started_at)} · Completed{" "}
              {formatDateTime(execution.completed_at)}
            </>
          ),
        },
        ...(execution.plan_summary
          ? [{ label: "Plan", value: planSummaryValue(execution) }]
          : []),
        { label: `Steps (${execution.steps.length})`, value: stepsValue(execution) },
        { label: "Event Timeline", value: eventsValue(events) },
        ...(result ? [{ label: "Crisp Result — structured facts only", value: resultValue(result) }] : []),
        ...(detailError
          ? [{ label: "Load Error", value: <span role="alert" className="text-red-400">{detailError}</span> }]
          : []),
        ...(actionError
          ? [{ label: "Action Error", value: <span role="alert" className="text-red-400">{actionError}</span> }]
          : []),
        ...(canCancel
          ? [
              {
                label: "Actions",
                value: (
                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={handleCancel}
                    className="rounded-md border border-red-700 px-3 py-1.5 text-xs font-semibold text-red-400 hover:bg-red-950 disabled:opacity-50"
                  >
                    {actionBusy ? "Cancelling…" : "Cancel Execution"}
                  </button>
                ),
              },
            ]
          : []),
      ]
    : [{ label: "Loading", value: "Loading execution…" }];

  return (
    <>
      <PageHeader
        title="Validation Operations"
        subtitle="Gated, authorized, bounded, non-destructive active validation — real DNS/TCP/TLS/HTTP observation against explicitly authorized canonical targets only. No exploit execution, no arbitrary scanning."
        actions={
          <>
            <button
              type="button"
              onClick={reloadAll}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
            >
              Start Validation
            </button>
          </>
        }
      />

      {showCreate ? (
        <StartValidationForm onClose={() => setShowCreate(false)} onCreated={handleCreated} />
      ) : null}

      <Panel title="Overview" className="mb-6">
        <AsyncContent state={summary}>
          {(s) => (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {Object.keys(STATUS_LABELS).map((status) => (
                <KpiTile
                  key={status}
                  label={STATUS_LABELS[status]}
                  value={s[status as keyof ValidationExecutionSummary] ?? 0}
                  tone={kpiTone(status)}
                />
              ))}
            </div>
          )}
        </AsyncContent>
      </Panel>

      <Panel
        title="Validation Executions"
        className="mb-8"
        right={
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter validation executions by lifecycle state"
            className="rounded-md border border-gray-800 bg-gray-950/80 px-2.5 py-1 text-xs text-gray-300"
          >
            <option value="">All lifecycle states</option>
            {Object.entries(STATUS_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        }
      >
        <AsyncContent
          state={executions}
          empty={(rows) => rows.length === 0}
          emptyLabel="No validation executions match the current filter."
        >
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows}
              rowKey={(e) => e.id}
              onRowClick={(e) => setSelectedId(e.id)}
              selectedKey={selectedId}
              emptyLabel="No validation executions match the current filter."
            />
          )}
        </AsyncContent>
      </Panel>

      <InvestigationDrawer
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={execution ? `Validation Execution` : "Validation Execution"}
        subtitle={selectedId ?? undefined}
        entityId={selectedId ?? undefined}
        fields={drawerFields}
      />
    </>
  );
}
