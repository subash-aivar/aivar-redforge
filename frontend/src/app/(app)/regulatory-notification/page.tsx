"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  AsyncContent,
  DataConsole,
  FormField,
  FormModal,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  useAsync,
  fmtTime,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  REGULATORY_REGIMES,
  getDeadlineDashboard,
  startClocks,
  listForIncident,
  createDraft,
  reviseDraft,
  finalizeDraft,
  submitNotification,
  configureJurisdictions,
  type DeadlineDashboardEntry,
  type IncidentNotification,
} from "@/lib/regulatoryNotification";
import { getMe } from "@/lib/auth";

export default function RegulatoryNotificationPage() {
  return (
    <Suspense fallback={<PageHeader title="Regulatory Notification" />}>
      <RegulatoryNotificationInner />
    </Suspense>
  );
}

function RegulatoryNotificationInner() {
  const incidentIdParam = useSearchParams().get("incidentId");
  const deadlines = useAsync(() => getDeadlineDashboard(), []);
  const [tab, setTab] = useState<"deadlines" | "incident" | "jurisdictions">(
    incidentIdParam ? "incident" : "deadlines"
  );
  const [selected, setSelected] = useState<DeadlineDashboardEntry | null>(null);
  const [showStartClocks, setShowStartClocks] = useState(false);

  const cols: ConsoleColumn<DeadlineDashboardEntry>[] = [
    { key: "regime", header: "Regime", width: "18%", render: (r) => <span className="text-gray-200">{r.regime.replace(/_/g, " ")}</span> },
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "deadline", header: "Deadline", width: "20%", render: (r) => fmtTime(r.deadline_at) },
    {
      key: "remaining",
      header: "Hours Remaining",
      width: "18%",
      render: (r) => (
        <span className={r.hours_remaining < 0 ? "font-bold text-red-400" : r.hours_remaining < 24 ? "font-bold text-amber-400" : "text-gray-300"}>
          {r.hours_remaining.toFixed(1)}h
        </span>
      ),
    },
    { key: "id", header: "Notification ID", width: "30%", render: (r) => <span className="font-mono text-[11px] text-gray-500">{r.notification_id}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Regulatory Notification"
        subtitle="Breach notification deadline tracking, drafting, and submission across regulatory regimes"
        actions={
          <button
            onClick={() => setShowStartClocks(true)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
          >
            Start Clocks
          </button>
        }
      />

      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["deadlines", "incident", "jurisdictions"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t === "deadlines" ? "Deadlines Dashboard" : t === "incident" ? "Incident Lookup" : "Jurisdictions"}
          </button>
        ))}
      </div>

      {tab === "deadlines" && (
        <AsyncContent state={deadlines} empty={(d) => d.length === 0} emptyLabel="No active regulatory notification clocks.">
          {(list) => (
            <>
              <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <KpiTile label="Active Clocks" value={list.length} />
                <KpiTile label="At Risk" value={list.filter((d) => d.status === "AT_RISK").length} tone="danger" />
                <KpiTile label="Breached" value={list.filter((d) => d.status === "BREACHED").length} tone="danger" />
                <KpiTile label="Approaching" value={list.filter((d) => d.status === "APPROACHING").length} tone="warning" />
              </div>
              <DataConsole columns={cols} rows={list} rowKey={(r) => r.notification_id} onRowClick={setSelected} emptyLabel="No active regulatory notification clocks." />
            </>
          )}
        </AsyncContent>
      )}

      {tab === "incident" && <IncidentLookupTab initialIncidentId={incidentIdParam ?? undefined} />}
      {tab === "jurisdictions" && <JurisdictionsTab />}

      {selected && (
        <InvestigationDrawer
          open
          title={selected.regime.replace(/_/g, " ")}
          subtitle={selected.notification_id}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Status", value: <StatusPill status={selected.status} /> },
            { label: "Deadline", value: fmtTime(selected.deadline_at) },
            { label: "Hours Remaining", value: `${selected.hours_remaining.toFixed(1)}h` },
          ]}
        />
      )}

      {showStartClocks && (
        <StartClocksModal onClose={() => setShowStartClocks(false)} onStarted={() => { deadlines.reload(); setShowStartClocks(false); }} />
      )}
    </>
  );
}

function IncidentLookupTab({ initialIncidentId }: { initialIncidentId?: string }) {
  const [incidentId, setIncidentId] = useState(initialIncidentId ?? "");
  const [notifications, setNotifications] = useState<IncidentNotification[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<IncidentNotification | null>(null);

  async function search(idOverride?: string) {
    const id = (idOverride ?? incidentId).trim();
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const rows = await listForIncident(id);
      setNotifications(rows);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lookup failed");
    } finally {
      setLoading(false);
    }
  }

  // Cross-module pivot from the Incident Response drawer
  // (`/regulatory-notification?incidentId=<real incident_id>`) — auto-run
  // the existing incident lookup instead of leaving the operator to
  // re-type the ID they already had selected.
  useEffect(() => {
    if (initialIncidentId) {
      search(initialIncidentId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialIncidentId]);

  const cols: ConsoleColumn<IncidentNotification>[] = [
    { key: "regime", header: "Regime", width: "20%", render: (r) => r.regime.replace(/_/g, " ") },
    { key: "status", header: "Status", width: "16%", render: (r) => <StatusPill status={r.status} /> },
    { key: "deadline", header: "Deadline", width: "20%", render: (r) => fmtTime(r.deadline_at) },
    { key: "submitted", header: "Submitted", width: "12%", render: (r) => (r.submitted ? "Yes" : "No") },
    { key: "advisory", header: "Advisory", width: "32%", render: (r) => <span className="text-xs text-gray-400">{r.advisory}</span> },
  ];

  return (
    <>
      <div className="mb-4 flex gap-2">
        <input
          value={incidentId}
          onChange={(e) => setIncidentId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
          placeholder="Incident ID"
          className="w-64 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />
        <button
          onClick={() => search()}
          disabled={loading}
          className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
        >
          {loading ? "Searching…" : "Search"}
        </button>
      </div>
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      {notifications !== null && (
        <DataConsole columns={cols} rows={notifications} rowKey={(r) => r.notification_id} onRowClick={setSelected} emptyLabel="No notifications found for this incident." />
      )}
      {selected && (
        <NotificationWorkflowDrawer
          notification={selected}
          onClose={() => setSelected(null)}
          onChanged={search}
        />
      )}
    </>
  );
}

function NotificationWorkflowDrawer({
  notification,
  onClose,
  onChanged,
}: {
  notification: IncidentNotification;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [content, setContent] = useState("");
  const [submissionMethod, setSubmissionMethod] = useState("");
  const [referenceNumber, setReferenceNumber] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function withActor<T>(fn: (actor: string) => Promise<T>): Promise<T | null> {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const me = await getMe().catch(() => null);
      const result = await fn(me?.email || "console");
      return result;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function handleDraft() {
    if (!content.trim()) {
      setError("Draft content is required.");
      return;
    }
    const r = await withActor((actor) => createDraft(notification.notification_id, content, actor));
    if (r) {
      setMessage(`Draft created (v${r.version}).`);
      onChanged();
    }
  }

  async function handleRevise() {
    if (!content.trim()) {
      setError("Revised content is required.");
      return;
    }
    const r = await withActor((actor) => reviseDraft(notification.notification_id, content, actor));
    if (r) {
      setMessage(`Draft revised (v${r.version}).`);
      onChanged();
    }
  }

  async function handleFinalize() {
    const r = await withActor((actor) => finalizeDraft(notification.notification_id, actor));
    if (r) {
      setMessage(`Draft finalized. Status: ${r.status}.`);
      onChanged();
    }
  }

  async function handleSubmit() {
    if (!submissionMethod.trim() || !referenceNumber.trim()) {
      setError("Submission method and reference number are required.");
      return;
    }
    const r = await withActor((actor) =>
      submitNotification(notification.notification_id, actor, submissionMethod, referenceNumber)
    );
    if (r) {
      setMessage(`Submitted. Reference: ${r.reference}.`);
      onChanged();
    }
  }

  const fields: DrawerField[] = [
    { label: "Status", value: <StatusPill status={notification.status} /> },
    { label: "Deadline", value: fmtTime(notification.deadline_at) },
    { label: "Advisory", value: notification.advisory },
    {
      label: "Draft Content",
      value: (
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={4}
          placeholder="Notification draft content…"
          className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
        />
      ),
    },
    {
      label: "Draft Actions",
      value: (
        <div className="flex gap-2">
          <button onClick={handleDraft} disabled={busy} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50">
            Create Draft
          </button>
          <button onClick={handleRevise} disabled={busy} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50">
            Revise Draft
          </button>
          <button onClick={handleFinalize} disabled={busy} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50">
            Finalize Draft
          </button>
        </div>
      ),
    },
    {
      label: "Submit to Authority",
      value: (
        <div className="space-y-2">
          <input
            value={submissionMethod}
            onChange={(e) => setSubmissionMethod(e.target.value)}
            placeholder="Submission method (e.g. portal, email)"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
          />
          <input
            value={referenceNumber}
            onChange={(e) => setReferenceNumber(e.target.value)}
            placeholder="Reference number"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
          />
          <button
            onClick={handleSubmit}
            disabled={busy || notification.submitted}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
          >
            {notification.submitted ? "Already Submitted" : "Submit Notification"}
          </button>
        </div>
      ),
    },
    ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
    ...(message ? [{ label: "Result", value: <span className="text-emerald-400">{message}</span> }] : []),
  ];

  return (
    <InvestigationDrawer
      open
      title={notification.regime.replace(/_/g, " ")}
      subtitle={notification.notification_id}
      onClose={onClose}
      fields={fields}
    />
  );
}

function StartClocksModal({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const [incidentId, setIncidentId] = useState("");
  const [selectedRegimes, setSelectedRegimes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggleRegime(r: string) {
    setSelectedRegimes((prev) => (prev.includes(r) ? prev.filter((x) => x !== r) : [...prev, r]));
  }

  async function submit() {
    if (!incidentId.trim()) {
      setError("Incident ID is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await startClocks(incidentId.trim(), selectedRegimes.length > 0 ? selectedRegimes : undefined);
      onStarted();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to start clocks");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="Start Regulatory Notification Clocks" onClose={onClose}>
      <div className="space-y-3">
        <FormField label="Incident ID" required>
          <input
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <fieldset>
          <legend className="mb-1 block text-xs text-gray-500">
            Regimes (leave empty to auto-derive from configured jurisdictions)
          </legend>
          <div className="flex flex-wrap gap-1.5">
            {REGULATORY_REGIMES.map((r) => (
              <button
                key={r}
                type="button"
                aria-pressed={selectedRegimes.includes(r)}
                onClick={() => toggleRegime(r)}
                className={`rounded-full border px-2.5 py-1 text-[11px] ${
                  selectedRegimes.includes(r)
                    ? "border-red-700 bg-red-950/50 text-red-300"
                    : "border-gray-700 text-gray-400 hover:text-gray-200"
                }`}
              >
                {r.replace(/_/g, " ")}
              </button>
            ))}
          </div>
        </fieldset>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-xs text-red-400">
          {error}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
          Cancel
        </button>
        <button
          disabled={busy}
          onClick={submit}
          className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
        >
          {busy ? "Starting…" : "Start Clocks"}
        </button>
      </div>
    </FormModal>
  );
}

function JurisdictionsTab() {
  const [selectedJurisdictions, setSelectedJurisdictions] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const JURISDICTIONS = ["EU", "US", "UK", "CA"];

  function toggle(j: string) {
    setSelectedJurisdictions((prev) => (prev.includes(j) ? prev.filter((x) => x !== j) : [...prev, j]));
  }

  async function save() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const r = await configureJurisdictions(selectedJurisdictions);
      setMessage(`Configured jurisdictions: ${r.jurisdictions.join(", ") || "none"}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to configure jurisdictions");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Configure Applicable Jurisdictions">
      <p className="mb-4 text-xs text-gray-500">
        Jurisdictions determine which regulatory regimes are automatically applied when starting
        notification clocks without explicit regime selection.
      </p>
      <div className="mb-4 flex flex-wrap gap-2">
        {JURISDICTIONS.map((j) => (
          <button
            key={j}
            onClick={() => toggle(j)}
            className={`rounded-full border px-3 py-1.5 text-xs ${
              selectedJurisdictions.includes(j)
                ? "border-red-700 bg-red-950/50 text-red-300"
                : "border-gray-700 text-gray-400 hover:text-gray-200"
            }`}
          >
            {j}
          </button>
        ))}
      </div>
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      {message && <p className="mb-3 text-xs text-emerald-400">{message}</p>}
      <button
        onClick={save}
        disabled={busy}
        className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
      >
        {busy ? "Saving…" : "Save Jurisdictions"}
      </button>
    </Panel>
  );
}
