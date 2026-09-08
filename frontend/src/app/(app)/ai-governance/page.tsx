"use client";

import Link from "next/link";
import { useCallback, useRef, useState } from "react";
import { FormField, FormModal, PageHeader, Panel, StatusPill } from "@/components/cc";
import {
  approveEnvelope,
  draftEnvelope,
  getAdvisories,
  suspendEnvelope,
  type Advisory,
  type Envelope,
} from "@/lib/aiGovernance";

/**
 * AI Agent Governance — envelope drafting and advisories lookup
 * (`ai_agent_governance` bounded context).
 *
 * Repository audit (Slice 5) found the previous version of this page
 * called three entirely fictional routes (`/policies`, `/violations`,
 * `/agents`) that do not exist in the backend — see
 * `lib/aiGovernance.ts`'s header comment for the full route audit.
 *
 * This context is command-only: there is no list or get-by-ID
 * endpoint for envelopes anywhere in the backend, only advisories
 * lookup by a known envelope ID. This is a real backend gap, honestly
 * reported rather than hidden behind a fabricated table — an operator
 * currently has no way to discover envelope IDs except by holding
 * onto the ID returned when drafting one. Draft/Approve/Suspend below
 * are real, working commands against the real API.
 */
export default function AIGovernancePage() {
  const [assetId, setAssetId] = useState("");
  const [draftedEnvelope, setDraftedEnvelope] = useState<Envelope | null>(null);
  const [draftError, setDraftError] = useState("");
  const [busy, setBusy] = useState(false);

  const [lookupId, setLookupId] = useState("");
  const [advisories, setAdvisories] = useState<Advisory[] | null>(null);
  const [advisoriesError, setAdvisoriesError] = useState("");

  const [showSuspendModal, setShowSuspendModal] = useState(false);
  const [suspendReason, setSuspendReason] = useState("");
  const [suspendReasonError, setSuspendReasonError] = useState("");
  const [suspendServerError, setSuspendServerError] = useState("");
  const [suspendSubmitting, setSuspendSubmitting] = useState(false);
  const suspendReasonRef = useRef<HTMLTextAreaElement>(null);

  async function handleDraft() {
    if (!assetId.trim()) return;
    setBusy(true);
    setDraftError("");
    try {
      setDraftedEnvelope(await draftEnvelope({ asset_id: assetId.trim() }));
    } catch {
      setDraftError("Failed to draft envelope — confirm the asset ID exists.");
    } finally {
      setBusy(false);
    }
  }

  async function handleApprove() {
    if (!draftedEnvelope) return;
    setBusy(true);
    try {
      setDraftedEnvelope(await approveEnvelope(draftedEnvelope.envelope_id, "analyst"));
    } catch {
      setDraftError("Approval failed.");
    } finally {
      setBusy(false);
    }
  }

  function openSuspendModal() {
    if (!draftedEnvelope) return;
    setSuspendReason("");
    setSuspendReasonError("");
    setSuspendServerError("");
    setShowSuspendModal(true);
  }

  // Stable identity: FormModal's focus-management effect depends on
  // `onClose` and must not re-run (re-focusing its first field) on
  // every keystroke inside its own reason textarea.
  const closeSuspendModal = useCallback(() => {
    setShowSuspendModal(false);
  }, []);

  async function handleSuspendSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!draftedEnvelope) return;
    if (!suspendReason.trim()) {
      setSuspendReasonError("Suspension reason is required.");
      suspendReasonRef.current?.focus();
      return;
    }
    setSuspendReasonError("");
    setSuspendServerError("");
    setSuspendSubmitting(true);
    try {
      setDraftedEnvelope(await suspendEnvelope(draftedEnvelope.envelope_id, suspendReason.trim()));
      setShowSuspendModal(false);
    } catch {
      setSuspendServerError("Suspend failed.");
    } finally {
      setSuspendSubmitting(false);
    }
  }

  async function handleLookupAdvisories() {
    if (!lookupId.trim()) return;
    setAdvisoriesError("");
    try {
      setAdvisories(await getAdvisories(lookupId.trim()));
    } catch {
      setAdvisories(null);
      setAdvisoriesError("No advisories found — confirm the envelope ID exists.");
    }
  }

  return (
    <>
      <PageHeader
        title="AI Agent Governance"
        subtitle="Action envelope authorization workflow — real command API, no fabricated policy/violation list"
        actions={
          <Link
            href="/ai-posture"
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            View Agent Deviations →
          </Link>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Draft Action Envelope">
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <FormField label="AI System Asset ID" required>
                <input
                  type="text"
                  value={assetId}
                  onChange={(e) => setAssetId(e.target.value)}
                  placeholder="UUID"
                  className="w-full rounded-md border border-gray-800 bg-gray-950/80 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
                />
              </FormField>
            </div>
            <button
              type="button"
              onClick={handleDraft}
              disabled={busy || !assetId.trim()}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
            >
              Draft
            </button>
          </div>
          {draftError && <p role="alert" className="mt-2 text-xs text-red-400">{draftError}</p>}
          {draftedEnvelope && (
            <div className="mt-3 rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-gray-400">{draftedEnvelope.envelope_id.slice(0, 18)}…</span>
                <StatusPill status={draftedEnvelope.state} />
              </div>
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleApprove}
                  className="rounded-md border border-emerald-800 bg-emerald-950/40 px-2.5 py-1 text-[11px] text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                >
                  Approve
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={openSuspendModal}
                  className="rounded-md border border-red-800 bg-red-950/40 px-2.5 py-1 text-[11px] text-red-300 hover:bg-red-950/70 disabled:opacity-50"
                >
                  Suspend
                </button>
              </div>
            </div>
          )}

          {showSuspendModal && draftedEnvelope && (
            <FormModal
              title={`Suspend Envelope ${draftedEnvelope.envelope_id.slice(0, 18)}…`}
              onClose={closeSuspendModal}
            >
              <form onSubmit={handleSuspendSubmit} noValidate>
                <FormField label="Suspension reason" required error={suspendReasonError || undefined}>
                  <textarea
                    ref={suspendReasonRef}
                    value={suspendReason}
                    onChange={(e) => setSuspendReason(e.target.value)}
                    rows={3}
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
                  />
                </FormField>
                {suspendServerError && (
                  <p role="alert" className="mt-2 text-xs text-red-400">
                    {suspendServerError}
                  </p>
                )}
                <div className="mt-4 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={closeSuspendModal}
                    className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={suspendSubmitting}
                    className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
                  >
                    {suspendSubmitting ? "Suspending…" : "Suspend Envelope"}
                  </button>
                </div>
              </form>
            </FormModal>
          )}
        </Panel>

        <Panel title="Look Up Envelope Advisories">
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <FormField label="Envelope ID" required>
                <input
                  type="text"
                  value={lookupId}
                  onChange={(e) => setLookupId(e.target.value)}
                  placeholder="UUID"
                  className="w-full rounded-md border border-gray-800 bg-gray-950/80 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
                />
              </FormField>
            </div>
            <button
              type="button"
              onClick={handleLookupAdvisories}
              disabled={!lookupId.trim()}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
            >
              Look Up
            </button>
          </div>
          {advisoriesError && <p role="alert" className="mt-2 text-xs text-red-400">{advisoriesError}</p>}
          {advisories && advisories.length === 0 && (
            <p className="mt-2 text-xs text-gray-500">No advisories for this envelope.</p>
          )}
          {advisories && advisories.length > 0 && (
            <div className="mt-3 space-y-2">
              {advisories.map((a, i) => (
                <div key={i} className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs">
                  <div className="text-gray-300">{a.deviation_type}</div>
                  <div className="mt-1 text-gray-500">{a.recommendation}</div>
                  <div className="mt-1 text-gray-600">Confirmed benign {a.confirmed_benign_count}×</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
