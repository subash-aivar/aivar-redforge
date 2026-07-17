"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useState } from "react";
import {
  AsyncContent,
  ErrorRow,
  PageHeader,
  Panel,
  fmtTime,
  useAsync,
} from "@/components/cc";
import { ApiError } from "@/lib/api";
import {
  beginEvidenceCollection,
  getAssessment,
  listAssessmentRecommendations,
  submitForConfirmation,
  technicallyValidate,
  type ControlAssessment,
  type EvidenceRecommendation,
} from "@/lib/compliance";
import {
  controlStatusPillClass,
  recommendationStatusPillClass,
  statusLabel,
} from "@/lib/compliance-helpers";

export default function AssessmentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [optimistic, setOptimistic] = useState<ControlAssessment | null>(null);

  const assessmentState = useAsync(() => getAssessment(id), [id]);
  const recState = useAsync(
    () => listAssessmentRecommendations(id, { limit: 100, offset: 0 }),
    [id]
  );

  const runAction = useCallback(
    async (fn: () => Promise<ControlAssessment>) => {
      setBusy(true);
      setActionError(null);
      try {
        const next = await fn();
        setOptimistic(next);
        assessmentState.reload();
        recState.reload();
      } catch (e) {
        setActionError(e instanceof ApiError ? e.message : "Action failed");
      } finally {
        setBusy(false);
      }
    },
    [assessmentState, recState]
  );

  return (
    <>
      <PageHeader
        title="Assessment Detail"
        subtitle={id}
        actions={
          <Link
            href="/compliance/assessments"
            className="text-xs text-gray-400 hover:text-red-300"
          >
            ← Workspace
          </Link>
        }
      />

      <AsyncContent state={assessmentState}>
        {(loaded) => {
          const a = optimistic ?? loaded;
          return (
            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Panel title="Status">
                  <span
                    className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${controlStatusPillClass(a.status)}`}
                  >
                    {statusLabel(a.status)}
                  </span>
                </Panel>
                <Panel title="Framework">
                  <div className="text-sm text-gray-200">{a.framework_key}</div>
                </Panel>
                <Panel title="Requirement">
                  <div className="font-mono text-xs text-gray-300">
                    {a.requirement_id}
                  </div>
                </Panel>
                <Panel title="Recommendations">
                  <div className="text-2xl font-bold tabular-nums text-gray-100">
                    {recState.data?.total ?? "—"}
                  </div>
                </Panel>
              </div>

              <Panel title="Lifecycle Actions">
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={busy || a.status !== "not_assessed"}
                    onClick={() => runAction(() => beginEvidenceCollection(a.id))}
                    className="rounded-md border border-sky-800 bg-sky-950/30 px-3 py-1.5 text-xs font-semibold text-sky-300 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
                  >
                    Begin Collection
                  </button>
                  <button
                    type="button"
                    disabled={busy || a.status !== "collecting_evidence"}
                    onClick={() => runAction(() => submitForConfirmation(a.id))}
                    className="rounded-md border border-amber-800 bg-amber-950/30 px-3 py-1.5 text-xs font-semibold text-amber-300 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
                  >
                    Submit for Confirmation
                  </button>
                  <button
                    type="button"
                    disabled={busy || a.status !== "pending_confirmation"}
                    onClick={() => runAction(() => technicallyValidate(a.id))}
                    className="rounded-md border border-emerald-800 bg-emerald-950/30 px-3 py-1.5 text-xs font-semibold text-emerald-300 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
                  >
                    Technically Validate
                  </button>
                </div>
                {actionError && (
                  <div className="mt-3">
                    <ErrorRow message={actionError} />
                  </div>
                )}
              </Panel>

              <Panel title="Linked Evidence">
                {a.evidence_links.length === 0 ? (
                  <p className="text-sm text-gray-500">No confirmed evidence links.</p>
                ) : (
                  <ul className="divide-y divide-gray-800">
                    {a.evidence_links.map((link) => (
                      <li key={`${link.evidence_id}-${link.confirmed_at}`} className="py-2 text-sm">
                        <div className="font-mono text-xs text-gray-200">
                          {link.evidence_id}
                        </div>
                        <div className="text-xs text-gray-500">
                          {link.confirmed_by} · {fmtTime(link.confirmed_at)}
                          {link.rationale ? ` · ${link.rationale}` : ""}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              <Panel
                title="Pending / Related Recommendations"
                right={
                  <Link
                    href={`/compliance/recommendations?assessment=${a.id}`}
                    className="text-[11px] text-red-400"
                  >
                    Queue →
                  </Link>
                }
              >
                <RecommendationList
                  loading={recState.loading}
                  items={recState.data?.items ?? []}
                />
              </Panel>

              <Panel title="History / Timeline">
                <ol className="space-y-2 text-sm">
                  <li className="border-l-2 border-gray-800 pl-3">
                    <div className="text-gray-200">Created</div>
                    <div className="text-xs text-gray-500">
                      {a.created_by} · {fmtTime(a.created_at)}
                    </div>
                  </li>
                  <li className="border-l-2 border-gray-800 pl-3">
                    <div className="text-gray-200">
                      Current status · {statusLabel(a.status)}
                    </div>
                    <div className="text-xs text-gray-500">{fmtTime(a.updated_at)}</div>
                  </li>
                  {a.evidence_links.map((link) => (
                    <li
                      key={`tl-${link.evidence_id}-${link.confirmed_at}`}
                      className="border-l-2 border-emerald-900 pl-3"
                    >
                      <div className="text-gray-200">Evidence confirmed</div>
                      <div className="text-xs text-gray-500">
                        {link.evidence_id} · {fmtTime(link.confirmed_at)}
                      </div>
                    </li>
                  ))}
                </ol>
              </Panel>

              {a.notes && (
                <Panel title="Notes">
                  <p className="whitespace-pre-wrap text-sm text-gray-300">{a.notes}</p>
                </Panel>
              )}
            </div>
          );
        }}
      </AsyncContent>
    </>
  );
}

function RecommendationList({
  loading,
  items,
}: {
  loading: boolean;
  items: EvidenceRecommendation[];
}) {
  if (loading) return <p className="text-sm text-gray-500">Loading recommendations…</p>;
  if (items.length === 0) {
    return <p className="text-sm text-gray-500">No recommendations for this assessment.</p>;
  }
  return (
    <ul className="divide-y divide-gray-800">
      {items.map((r) => (
        <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-sm">
          <div className="min-w-0">
            <div className="truncate text-gray-200">{r.rationale || r.dedup_key}</div>
            <div className="text-[11px] text-gray-500">
              {r.primary_reference.source_kind} · {r.confidence} · score{" "}
              {r.score.toFixed(2)}
            </div>
          </div>
          <span
            className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${recommendationStatusPillClass(r.status)}`}
          >
            {statusLabel(r.status)}
          </span>
        </li>
      ))}
    </ul>
  );
}
