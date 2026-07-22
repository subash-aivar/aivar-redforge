"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  listReviews,
  createReview,
  addLesson,
  addAction,
  finalizeReview,
  type LessonsLearnedReview,
} from "@/lib/lessonsLearned";

export default function LessonsLearnedPage() {
  const reviews = useAsync(() => listReviews(), []);
  const [selected, setSelected] = useState<LessonsLearnedReview | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState(false);

  const columns: ConsoleColumn<LessonsLearnedReview>[] = [
    { key: "incident", header: "Incident", width: "24%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.incident_id.slice(0, 12)}…</span>
    )},
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "lessons", header: "Lessons", width: "10%", render: (r) => `${r.lessons.length}` },
    { key: "actions", header: "Actions", width: "10%", render: (r) => `${r.actions.length}` },
    { key: "techniques", header: "Techniques", width: "18%", render: (r) => r.technique_ids.slice(0, 2).join(", ") || "—" },
    { key: "created", header: "Created", width: "14%", render: (r) => fmtTime(r.created_at) },
    { key: "id", header: "ID", width: "10%", render: (r) => (
      <span className="font-mono text-[10px] text-gray-600">{r.review_id.slice(0, 8)}…</span>
    )},
  ];

  return (
    <>
      <PageHeader
        title="Lessons Learned"
        subtitle="Post-incident reviews, findings, and improvement actions"
        actions={
          <div className="flex gap-2">
            <button type="button" onClick={() => setShowCreate(true)} className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50">
              New Review
            </button>
            <button type="button" onClick={() => reviews.reload()} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300">
              Refresh
            </button>
          </div>
        }
      />

      {showCreate && <CreateReviewForm onClose={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); reviews.reload(); }} />}

      <AsyncContent state={reviews}>
        {(list) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Reviews" value={list.length} />
              <KpiTile label="In Progress" value={list.filter(r => r.status === "in_progress" || r.status === "open").length} tone="warning" />
              <KpiTile label="Finalized" value={list.filter(r => r.status === "finalized" || r.status === "closed").length} tone="ok" />
              <KpiTile label="Total Actions" value={list.reduce((sum, r) => sum + r.actions.length, 0)} />
            </div>
            <DataConsole
              columns={columns}
              rows={list}
              rowKey={(r) => r.review_id}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No post-incident reviews. Create one after an incident is resolved."
            />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          title={`Review: ${selected.incident_id.slice(0, 12)}…`}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Status", value: <StatusPill status={selected.status} /> },
            { label: "Incident", value: <span className="font-mono">{selected.incident_id}</span> },
            ...(selected.lessons.length > 0
              ? [{
                  label: `Lessons (${selected.lessons.length})`,
                  value: (
                    <div className="divide-y divide-gray-800">
                      {selected.lessons.map((l) => (
                        <div key={l.lesson_id} className="py-2">
                          <span className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400">{l.category}</span>
                          <p className="mt-1 text-sm text-gray-300">{l.description}</p>
                          <p className="mt-0.5 text-xs text-gray-500">Impact: {l.impact_summary}</p>
                        </div>
                      ))}
                    </div>
                  ),
                }]
              : []),
            ...(selected.actions.length > 0
              ? [{
                  label: `Actions (${selected.actions.length})`,
                  value: (
                    <div className="divide-y divide-gray-800">
                      {selected.actions.map((a) => (
                        <div key={a.action_id} className="flex items-center justify-between py-2">
                          <div>
                            <span className="text-sm text-gray-200">{a.title}</span>
                            <span className="ml-2 text-xs text-gray-500">→ {a.owner}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-gray-500">{a.priority}</span>
                            <StatusPill status={a.status} />
                          </div>
                        </div>
                      ))}
                    </div>
                  ),
                }]
              : []),
          ]}
        />
      )}
    </>
  );
}

function CreateReviewForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [incidentId, setIncidentId] = useState("");
  const [techniques, setTechniques] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await createReview(incidentId, techniques.split(",").map(t => t.trim()).filter(Boolean));
      onCreated();
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
