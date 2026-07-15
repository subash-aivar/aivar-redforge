"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listPendingRecommendations,
  approveRecommendation,
  rejectRecommendation,
  type MitigationRecommendation,
} from "@/lib/ddos";

function ApprovalStatusBadge({ status }: { status: string }) {
  const cls =
    status === "APPROVED" ? "border-emerald-800 bg-emerald-950 text-emerald-400" :
    status === "REJECTED" ? "border-gray-700 bg-gray-800 text-gray-500" :
    "border-orange-800 bg-orange-950 text-orange-400";
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${cls}`}>
      {status}
    </span>
  );
}

export default function MitigationCenterPage() {
  const [pending, setPending] = useState<MitigationRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [rejectReasons, setRejectReasons] = useState<Record<string, string>>({});

  const load = async () => {
    try {
      const recs = await listPendingRecommendations();
      setPending(recs);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load recommendations");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 15_000);
    return () => clearInterval(iv);
  }, []);

  const handleApprove = async (recId: string) => {
    try {
      setActionError(null);
      await approveRecommendation(recId);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to approve");
    }
  };

  const handleReject = async (recId: string) => {
    try {
      setActionError(null);
      const reason = rejectReasons[recId] || "Rejected by operator";
      await rejectRecommendation(recId, reason);
      setRejectReasons(r => ({ ...r, [recId]: "" }));
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to reject");
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Mitigation Center</h1>
          <p className="mt-1 text-sm text-gray-400">
            Operator-gated mitigation approval — RECOMMEND_ONLY mode · No automated execution
          </p>
        </div>
        <Link href="/ddos" className="text-sm text-blue-400 hover:underline">← DDoS Overview</Link>
      </div>

      {/* Safety notice */}
      <div className="rounded-xl border border-gray-700 bg-gray-900 p-5">
        <h3 className="mb-2 text-sm font-semibold text-gray-300">⛨ Mitigation Safety Architecture</h3>
        <div className="grid gap-3 text-xs text-gray-400 md:grid-cols-3">
          <div>
            <div className="font-semibold text-gray-300 mb-1">RECOMMEND_ONLY (Default)</div>
            Detection creates recommendations. No action is taken without explicit operator approval.
          </div>
          <div>
            <div className="font-semibold text-gray-300 mb-1">Approval Required</div>
            DDOS_MITIGATION_APPROVE permission required. Every approval is audit-logged with actor identity.
          </div>
          <div>
            <div className="font-semibold text-gray-300 mb-1">NOT CONFIGURED</div>
            No execution adapter is configured in M19. Recommendations are documented for manual operator action.
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-4 text-red-300">{error}</div>
      )}
      {actionError && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-3 text-sm text-red-300">{actionError}</div>
      )}

      {loading ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-500">
          Loading recommendations…
        </div>
      ) : pending.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center">
          <div className="text-4xl mb-4">✓</div>
          <div className="text-lg font-medium text-gray-300">No pending recommendations</div>
          <div className="mt-1 text-sm text-gray-500">
            Recommendations appear automatically when DDoS attacks are detected
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="text-sm font-medium text-orange-400">
            {pending.length} recommendation{pending.length !== 1 ? "s" : ""} awaiting approval
          </div>
          {pending.map(rec => (
            <div key={rec.id} className="rounded-xl border border-orange-900 bg-orange-950/20 p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-orange-300">{rec.recommendation_type}</span>
                    <ApprovalStatusBadge status={rec.approval_status} />
                  </div>
                  <div className="mt-2 text-sm text-gray-200">{rec.description}</div>

                  {/* Detail */}
                  {rec.recommendation_detail && (
                    <div className="mt-3 rounded-lg border border-gray-800 bg-gray-900 p-3">
                      <div className="text-xs font-semibold text-gray-500 mb-2">Recommendation Detail</div>
                      <div className="space-y-1 text-xs text-gray-400">
                        {Object.entries(rec.recommendation_detail).filter(([k]) => k !== "matched_signals").map(([k, v]) => (
                          <div key={k} className="flex gap-2">
                            <span className="text-gray-500 shrink-0">{k.replace(/_/g, " ")}:</span>
                            <span className="text-gray-300 break-all">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-3 flex flex-col gap-2">
                    <div className="text-xs text-gray-500">
                      Incident: <Link href={`/ddos/incidents/${rec.incident_id}`} className="text-blue-400 hover:underline font-mono">{rec.incident_id.slice(-8).toUpperCase()}</Link>
                    </div>
                    <div className="text-xs text-gray-500">
                      Execution provider: <span className="font-mono text-gray-400">{rec.provider_type ?? "NOT CONFIGURED"}</span>
                    </div>
                    <div className="text-xs text-gray-600">{new Date(rec.created_at).toLocaleString()}</div>
                  </div>

                  {/* Reject reason input */}
                  {rec.approval_status === "PENDING" && (
                    <div className="mt-3">
                      <input
                        value={rejectReasons[rec.id] ?? ""}
                        onChange={e => setRejectReasons(r => ({ ...r, [rec.id]: e.target.value }))}
                        placeholder="Rejection reason (optional)"
                        className="w-full max-w-md rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 placeholder-gray-600"
                      />
                    </div>
                  )}
                </div>

                {rec.approval_status === "PENDING" && (
                  <div className="flex flex-col gap-2 flex-shrink-0">
                    <button
                      onClick={() => handleApprove(rec.id)}
                      className="rounded-lg border border-emerald-800 bg-emerald-950 px-4 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-900"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleReject(rec.id)}
                      className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-semibold text-gray-400 hover:bg-gray-700"
                    >
                      Reject
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
