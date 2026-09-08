"use client";

import { useCallback, useRef, useState } from "react";
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
  type ConsoleColumn,
} from "@/components/cc";
import {
  listCandidates,
  promoteCandidate,
  rejectCandidate,
  type ThreatHuntCandidate,
} from "@/lib/threat-hunt";

export default function ThreatHuntPage() {
  const candidates = useAsync(() => listCandidates(), []);
  const [selected, setSelected] = useState<ThreatHuntCandidate | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [showRejectModal, setShowRejectModal] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const [rejectReasonError, setRejectReasonError] = useState("");
  const [rejectServerError, setRejectServerError] = useState("");
  const [rejectSubmitting, setRejectSubmitting] = useState(false);
  const rejectReasonRef = useRef<HTMLTextAreaElement>(null);

  // Stable identity is required: InvestigationDrawer's focus-management
  // effect depends on `onClose`, and any inline arrow function here
  // would get a new identity on every ThreatHuntPage re-render — e.g.
  // every keystroke in the reject-reason field below — re-running that
  // effect and stealing focus back to the drawer's own Close button.
  const closeDrawer = useCallback(() => {
    setSelected(null);
    setActionError(null);
  }, []);

  async function handlePromote(c: ThreatHuntCandidate) {
    const versionId = window.prompt("Promoted rule version ID (UUID):");
    if (!versionId) return;
    setBusy(true);
    setActionError(null);
    try {
      await promoteCandidate(c.candidate_id, "analyst", versionId);
      setSelected(null);
      candidates.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Promote failed");
    } finally {
      setBusy(false);
    }
  }

  function openRejectModal() {
    setRejectReason("");
    setRejectReasonError("");
    setRejectServerError("");
    setShowRejectModal(true);
  }

  // Stable identity for the same reason as closeDrawer above — FormModal's
  // own focus-management effect depends on `onClose`, and it must not
  // re-run (and steal focus back to its first field) on every keystroke
  // inside its own reason textarea.
  const closeRejectModal = useCallback(() => {
    setShowRejectModal(false);
  }, []);

  async function handleRejectSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selected) return;
    if (!rejectReason.trim()) {
      setRejectReasonError("Rejection reason is required.");
      rejectReasonRef.current?.focus();
      return;
    }
    setRejectReasonError("");
    setRejectServerError("");
    setRejectSubmitting(true);
    try {
      await rejectCandidate(selected.candidate_id, "analyst", rejectReason.trim());
      setShowRejectModal(false);
      setSelected(null);
      candidates.reload();
    } catch (e) {
      setRejectServerError(e instanceof Error ? e.message : "Reject failed");
    } finally {
      setRejectSubmitting(false);
    }
  }

  const columns: ConsoleColumn<ThreatHuntCandidate>[] = [
    { key: "id", header: "Candidate", width: "22%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.candidate_id.slice(0, 12)}…</span>
    ) },
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "confidence", header: "Confidence", width: "12%", render: (r) => (
      <span className="tabular-nums">{(r.confidence_score * 100).toFixed(0)}%</span>
    ) },
    { key: "format", header: "Rule Format", width: "14%", render: (r) => r.detection_rule_format },
    { key: "techniques", header: "Techniques", width: "24%", render: (r) => r.technique_coverage.join(", ") || "—" },
    { key: "signals", header: "Signals", width: "10%", render: (r) => r.anomaly_signal_count },
  ];

  return (
    <>
      <PageHeader
        title="Threat Hunt"
        subtitle="AI-surfaced hunt candidates awaiting analyst triage"
        actions={
          <button
            type="button"
            onClick={() => candidates.reload()}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <AsyncContent state={candidates} emptyLabel="No hunt candidates yet.">
        {(rows) => {
          const pending = rows.filter((r) => r.status.toLowerCase().includes("pending")).length;
          const promoted = rows.filter((r) => r.status.toLowerCase() === "promoted").length;
          return (
            <>
              <div className="mb-6 grid gap-4 sm:grid-cols-3">
                <KpiTile label="Total Candidates" value={rows.length} />
                <KpiTile label="Pending Review" value={pending} tone={pending > 0 ? "warning" : "ok"} />
                <KpiTile label="Promoted" value={promoted} tone="ok" />
              </div>

              <Panel title="Hunt Candidates">
                <DataConsole
                  columns={columns}
                  rows={rows}
                  rowKey={(r) => r.candidate_id}
                  onRowClick={(r) => setSelected(r)}
                  selectedKey={selected?.candidate_id ?? null}
                  emptyLabel="No hunt candidates."
                />
              </Panel>
            </>
          );
        }}
      </AsyncContent>

      <InvestigationDrawer
        open={selected !== null}
        onClose={closeDrawer}
        title={selected ? `Candidate ${selected.candidate_id.slice(0, 12)}…` : ""}
        subtitle={selected?.status}
        fields={
          selected
            ? [
                { label: "Status", value: <StatusPill status={selected.status} /> },
                { label: "Confidence Score", value: `${(selected.confidence_score * 100).toFixed(1)}%` },
                { label: "Detection Rule Format", value: selected.detection_rule_format },
                { label: "Technique Coverage", value: selected.technique_coverage.join(", ") || "—" },
                { label: "Anomaly Signal Count", value: selected.anomaly_signal_count },
                ...(actionError ? [{ label: "Action Error", value: <span role="alert" className="text-red-400">{actionError}</span> }] : []),
                {
                  label: "Actions",
                  value: (
                    <div className="flex gap-2 pt-1">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => selected && handlePromote(selected)}
                        className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                      >
                        Promote
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={openRejectModal}
                        className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 disabled:opacity-50"
                      >
                        Reject
                      </button>
                    </div>
                  ),
                },
              ]
            : []
        }
      />

      {showRejectModal && selected && (
        <FormModal
          title={`Reject Candidate ${selected.candidate_id.slice(0, 12)}…`}
          onClose={closeRejectModal}
        >
          <form onSubmit={handleRejectSubmit} noValidate>
            <FormField label="Rejection reason" required error={rejectReasonError || undefined}>
              <textarea
                ref={rejectReasonRef}
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                rows={3}
                className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
              />
            </FormField>
            {rejectServerError && (
              <p role="alert" className="mt-2 text-xs text-red-400">
                {rejectServerError}
              </p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={closeRejectModal}
                className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={rejectSubmitting}
                className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
              >
                {rejectSubmitting ? "Rejecting…" : "Reject Candidate"}
              </button>
            </div>
          </form>
        </FormModal>
      )}
    </>
  );
}
