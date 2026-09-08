"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { FormField, InvestigationDrawer, PageHeader, Panel, StatusPill } from "@/components/cc";
import {
  getProvenance,
  manualResetVerification,
  verifyProvenance,
  type ModelProvenance,
} from "@/lib/aiSupplyChain";

/**
 * AI Supply Chain — provenance lookup and verification tool
 * (`ai_supply_chain` bounded context).
 *
 * Repository audit (Slice 5) found the previous version of this page
 * called four entirely fictional routes (`/artifacts`, `/artifacts/
 * {id}/scan`, `/risks`) that do not exist in the backend — see
 * `lib/aiSupplyChain.ts`'s header comment for the full route audit.
 *
 * This context is command/get-by-id only in the backend — there is no
 * list endpoint for provenance records. Rather than fabricate one,
 * this page is honestly a lookup + action tool: enter (or arrive via
 * `?highlight=<provenance_id>` from the AI Security Operations
 * Center's Supply Chain Integrity panel) a real provenance ID and act
 * on it. The real list view for supply-chain data lives on
 * `/ai-posture` (`reports/supply-chain-integrity`), linked below.
 */
export default function AISupplyChainInner() {
  const highlightId = useSearchParams().get("highlight");
  const [provenanceId, setProvenanceId] = useState(highlightId ?? "");
  const [provenance, setProvenance] = useState<ModelProvenance | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [retrievalUri, setRetrievalUri] = useState("");

  useEffect(() => {
    if (highlightId) void lookup(highlightId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightId]);

  async function lookup(id: string) {
    if (!id.trim()) return;
    setError("");
    setBusy(true);
    try {
      setProvenance(await getProvenance(id.trim()));
    } catch {
      setProvenance(null);
      setError("No provenance record found for this ID.");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerify() {
    if (!provenance || !retrievalUri.trim()) return;
    setBusy(true);
    setError("");
    try {
      setProvenance(await verifyProvenance(provenance.provenance_id, { retrieval_uri: retrievalUri.trim() }));
      setRetrievalUri("");
    } catch {
      setError("Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleManualReset() {
    if (!provenance) return;
    setBusy(true);
    setError("");
    try {
      setProvenance(await manualResetVerification(provenance.provenance_id));
    } catch {
      setError("Manual reset failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="AI Supply Chain — Provenance Lookup"
        subtitle="Model provenance verification and manual reset — real list view lives on AI Security Operations Center"
        actions={
          <Link
            href="/ai-posture"
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            View Supply Chain Integrity →
          </Link>
        }
      />

      <Panel title="Look Up Provenance Record">
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <FormField label="Provenance ID" required>
              <input
                type="text"
                value={provenanceId}
                onChange={(e) => setProvenanceId(e.target.value)}
                placeholder="UUID"
                className="w-full rounded-md border border-gray-800 bg-gray-950/80 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
              />
            </FormField>
          </div>
          <button
            type="button"
            onClick={() => lookup(provenanceId)}
            disabled={busy || !provenanceId.trim()}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
          >
            Look Up
          </button>
        </div>
        {error && <p role="alert" className="mt-2 text-xs text-red-400">{error}</p>}
      </Panel>

      {provenance && (
        <InvestigationDrawer
          open
          onClose={() => setProvenance(null)}
          title={provenance.model_origin}
          subtitle={`Asset ${provenance.ai_system_asset_id.slice(0, 14)}…`}
          entityId={provenance.provenance_id}
          fields={[
            { label: "Integrity Status", value: <StatusPill status={provenance.integrity_status} /> },
            { label: "Operational Status", value: <StatusPill status={provenance.operational_status} /> },
            { label: "Verification Method", value: provenance.verification_method_latest ?? "Not yet verified" },
            { label: "Trust Delegation Note", value: provenance.trust_delegation_note_latest || "—" },
            { label: "Chain Entries", value: provenance.chain_entry_count },
            {
              label: "Consecutive Failures",
              value: (
                <span className={provenance.consecutive_failures > 0 ? "text-red-400" : "text-emerald-400"}>
                  {provenance.consecutive_failures}
                </span>
              ),
            },
            { label: "Artifact Size", value: `${(provenance.artifact_size_bytes / 1_000_000).toFixed(2)} MB` },
            {
              label: "Actions",
              value: (
                <div className="space-y-2">
                  <div className="flex items-end gap-2">
                    <div className="flex-1">
                      <FormField label="Retrieval URI to verify against" required>
                        <input
                          type="url"
                          value={retrievalUri}
                          onChange={(e) => setRetrievalUri(e.target.value)}
                          placeholder="https://…"
                          className="w-full rounded-md border border-gray-800 bg-gray-950/80 px-2 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
                        />
                      </FormField>
                    </div>
                    <button
                      type="button"
                      disabled={busy || !retrievalUri.trim()}
                      onClick={handleVerify}
                      className="rounded-md border border-emerald-800 bg-emerald-950/40 px-2.5 py-1 text-xs text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                    >
                      Verify
                    </button>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={handleManualReset}
                    className="rounded-md border border-amber-800 bg-amber-950/40 px-2.5 py-1 text-xs text-amber-300 hover:bg-amber-950/70 disabled:opacity-50"
                  >
                    Manual Reset
                  </button>
                </div>
              ),
            },
          ]}
        />
      )}
    </>
  );
}
