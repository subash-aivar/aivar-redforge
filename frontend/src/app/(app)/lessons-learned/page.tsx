"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ApiError } from "@/lib/api";
import { KpiTile, PageHeader, Panel, StatusPill } from "@/components/cc";
import {
  addLesson,
  createReview,
  finalizeReview,
  getForIncident,
  type LessonsLearnedRecord,
} from "@/lib/lessonsLearned";

export default function LessonsLearnedPage() {
  return (
    <Suspense fallback={<PageHeader title="Lessons Learned" />}>
      <LessonsLearnedInner />
    </Suspense>
  );
}

function LessonsLearnedInner() {
  // The backend has no list-all-reviews endpoint — only a per-incident
  // lookup (`GET /lessons-learned/incident/{incident_id}`), verified
  // against `lessons_learned/api/v1/routes.py`. Cross-module pivot from
  // the Incident Response drawer (`?incidentId=<real incident_id>`)
  // pre-fills and auto-runs this lookup, same pattern as
  // Regulatory Notification.
  const initialIncidentId = useSearchParams().get("incidentId") ?? "";
  const [incidentId, setIncidentId] = useState(initialIncidentId);
  const [record, setRecord] = useState<LessonsLearnedRecord | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showCreate, setShowCreate] = useState(false);

  async function search(idOverride?: string) {
    const id = (idOverride ?? incidentId).trim();
    if (!id) return;
    setLoading(true);
    setError("");
    setNotFound(false);
    setRecord(null);
    try {
      setRecord(await getForIncident(id));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setNotFound(true);
      } else {
        setError(e instanceof Error ? e.message : "Lookup failed");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (initialIncidentId) search(initialIncidentId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialIncidentId]);

  return (
    <>
      <PageHeader
        title="Lessons Learned"
        subtitle="Post-incident review, findings, and improvement actions — looked up by incident"
      />

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
          {loading ? "Looking up…" : "Look Up"}
        </button>
      </div>

      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}

      {notFound && (
        <div className="mb-4 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-400">
          No post-incident review exists for this incident yet.
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="ml-3 rounded-md border border-red-800 bg-red-950/40 px-2 py-1 text-xs text-red-300 hover:bg-red-900/50"
          >
            Create Review
          </button>
        </div>
      )}

      {showCreate && (
        <CreateReviewForm
          initialIncidentId={incidentId}
          onClose={() => setShowCreate(false)}
          onCreated={(id) => { setShowCreate(false); search(id); }}
        />
      )}

      {record && (
        <>
          <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <KpiTile label="Status" value={record.status} />
            <KpiTile label="Lessons Captured" value={record.lessons} />
            <KpiTile label="Improvement Actions" value={record.actions} />
            <KpiTile label="Quality Score" value={record.quality_score.toFixed(1)} />
          </div>

          <Panel title="Review Detail">
            <div className="space-y-3 p-4 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-500">Incident</span>
                <span className="font-mono text-gray-300">{record.incident_id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-500">Status</span>
                <StatusPill status={record.status} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-500">MITRE Techniques</span>
                <span className="text-gray-300">{record.techniques.join(", ") || "—"}</span>
              </div>
            </div>
          </Panel>

          <RecordActions record={record} busy={busy} setBusy={setBusy} onChanged={() => search(record.incident_id)} />
        </>
      )}
    </>
  );
}

function RecordActions({
  record,
  busy,
  setBusy,
  onChanged,
}: {
  record: LessonsLearnedRecord;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onChanged: () => void;
}) {
  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [impact, setImpact] = useState("");
  const [error, setError] = useState("");

  async function submitLesson(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await addLesson(record.ll_id, { category, description, impact_summary: impact });
      setCategory("");
      setDescription("");
      setImpact("");
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add lesson");
    } finally {
      setBusy(false);
    }
  }

  async function finalize() {
    setBusy(true);
    setError("");
    try {
      await finalizeReview(record.ll_id);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to finalize review");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Add Lesson" className="mt-4">
      <form onSubmit={submitLesson} className="space-y-3 p-4">
        <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Category" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        <input value={impact} onChange={(e) => setImpact(e.target.value)} placeholder="Impact summary" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex gap-2">
          <button type="submit" disabled={busy} className="rounded-md bg-red-600 px-4 py-2 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50">
            Add Lesson
          </button>
          {record.status !== "finalized" && (
            <button type="button" onClick={finalize} disabled={busy} className="rounded-md border border-gray-700 px-4 py-2 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50">
              Finalize Review
            </button>
          )}
        </div>
      </form>
    </Panel>
  );
}

function CreateReviewForm({
  initialIncidentId,
  onClose,
  onCreated,
}: {
  initialIncidentId?: string;
  onClose: () => void;
  onCreated: (incidentId: string) => void;
}) {
  const [incidentId, setIncidentId] = useState(initialIncidentId ?? "");
  const [techniques, setTechniques] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await createReview(incidentId, techniques.split(",").map((t) => t.trim()).filter(Boolean));
      onCreated(incidentId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel title="Create Post-Incident Review" className="mb-6">
      <form onSubmit={submit} className="space-y-3 p-4">
        <input value={incidentId} onChange={(e) => setIncidentId(e.target.value)} placeholder="Incident ID" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        <input value={techniques} onChange={(e) => setTechniques(e.target.value)} placeholder="MITRE technique IDs (comma-separated, optional)" className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex gap-2">
          <button type="submit" disabled={loading} className="rounded-md bg-red-600 px-4 py-2 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50">
            {loading ? "Creating…" : "Create Review"}
          </button>
          <button type="button" onClick={onClose} className="rounded-md border border-gray-700 px-4 py-2 text-xs text-gray-400 hover:text-white">Cancel</button>
        </div>
      </form>
    </Panel>
  );
}
