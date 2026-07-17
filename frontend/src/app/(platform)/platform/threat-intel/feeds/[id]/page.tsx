"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import {
  getFeed,
  listSyncRuns,
  activateFeed,
  pauseFeed,
  disableFeed,
  triggerFeedSync,
  feedStatusColor,
  syncRunStatusColor,
  formatInterval,
  SOURCE_KIND_LABELS,
  type Feed,
  type FeedSyncRun,
} from "@/lib/feedSync";

export default function FeedDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [feed, setFeed] = useState<Feed | null>(null);
  const [runs, setRuns] = useState<FeedSyncRun[] | null>(null);
  const [feedError, setFeedError] = useState("");
  const [actionError, setActionError] = useState("");

  function loadFeed() {
    getFeed(id)
      .then(setFeed)
      .catch(() => setFeedError("Feed not found or access denied."));
  }

  function loadRuns() {
    listSyncRuns(id, { limit: 20 })
      .then((r) => setRuns(r.items))
      .catch(() => setRuns([]));
  }

  useEffect(() => {
    loadFeed();
    loadRuns();
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function doAction(action: "activate" | "pause" | "disable" | "sync") {
    setActionError("");
    try {
      if (action === "activate") await activateFeed(id);
      else if (action === "pause") await pauseFeed(id);
      else if (action === "disable") await disableFeed(id);
      else await triggerFeedSync(id);
      loadFeed();
      loadRuns();
    } catch {
      setActionError(`Action '${action}' failed.`);
    }
  }

  if (feedError) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
        {feedError}
      </div>
    );
  }

  if (!feed) return <div className="text-sm text-gray-500">Loading…</div>;

  return (
    <div>
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/platform/threat-intel/feeds" className="text-xs text-gray-600 hover:text-gray-400">
              ← Feeds
            </Link>
          </div>
          <h1 className="mt-1 text-2xl font-bold text-white">{feed.display_name}</h1>
          <div className="mt-1 flex flex-wrap gap-3 text-xs text-gray-500">
            <span className="font-mono">{feed.feed_key}</span>
            <span>{SOURCE_KIND_LABELS[feed.source_kind] ?? feed.source_kind}</span>
            <span>every {formatInterval(feed.schedule_interval_seconds)}</span>
          </div>
        </div>
        <span
          className={`rounded border px-2 py-1 text-xs font-medium ${feedStatusColor(feed.status)}`}
        >
          {feed.status}
        </span>
      </div>

      {actionError && (
        <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-300">
          {actionError}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {feed.status !== "active" && (
          <ActionBtn label="Activate" onClick={() => doAction("activate")} color="emerald" />
        )}
        {feed.status === "active" && (
          <ActionBtn label="Pause" onClick={() => doAction("pause")} color="yellow" />
        )}
        {feed.status !== "disabled" && (
          <ActionBtn label="Disable" onClick={() => doAction("disable")} color="red" />
        )}
        <ActionBtn label="Sync Now" onClick={() => doAction("sync")} color="purple" />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Last Sync" value={feed.last_sync_completed_at ? new Date(feed.last_sync_completed_at).toLocaleString() : "Never"} />
        <StatCard label="Last Status" value={feed.last_sync_status ?? "—"} />
        <StatCard label="Consecutive Failures" value={String(feed.consecutive_failure_count)} />
      </div>

      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="text-sm font-medium text-gray-300">Connector Config</h2>
        <pre className="mt-2 overflow-x-auto text-xs text-gray-500">
          {JSON.stringify(feed.connector_config, null, 2)}
        </pre>
      </div>

      <div className="mt-6">
        <h2 className="text-sm font-medium text-gray-300">Sync Run History</h2>
        {!runs ? (
          <div className="mt-2 text-sm text-gray-500">Loading…</div>
        ) : runs.length === 0 ? (
          <div className="mt-2 text-sm text-gray-500">No sync runs yet.</div>
        ) : (
          <div className="mt-2 overflow-x-auto rounded-xl border border-gray-800">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500">
                  <th className="px-4 py-2 text-left">Status</th>
                  <th className="px-4 py-2 text-left">Trigger</th>
                  <th className="px-4 py-2 text-left">Fetched</th>
                  <th className="px-4 py-2 text-left">Processed</th>
                  <th className="px-4 py-2 text-left">Failed</th>
                  <th className="px-4 py-2 text-left">Started</th>
                  <th className="px-4 py-2 text-left">Duration</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => {
                  const duration =
                    r.finished_at && r.started_at
                      ? ((new Date(r.finished_at).getTime() - new Date(r.started_at).getTime()) / 1000).toFixed(1) + "s"
                      : "—";
                  return (
                    <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                      <td className="px-4 py-2">
                        <span className={`rounded border px-1.5 py-0.5 text-xs ${syncRunStatusColor(r.status)}`}>
                          {r.status}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-500">{r.trigger}</td>
                      <td className="px-4 py-2 text-xs text-gray-400">{r.items_fetched}</td>
                      <td className="px-4 py-2 text-xs text-gray-400">{r.items_processed}</td>
                      <td className="px-4 py-2 text-xs text-red-400">{r.items_failed > 0 ? r.items_failed : "—"}</td>
                      <td className="px-4 py-2 text-xs text-gray-500">
                        {new Date(r.started_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-500">{duration}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="mt-1 text-sm font-medium text-gray-200">{value}</div>
    </div>
  );
}

function ActionBtn({
  label,
  onClick,
  color,
}: {
  label: string;
  onClick: () => void;
  color: "emerald" | "yellow" | "red" | "purple";
}) {
  const colors = {
    emerald: "border-emerald-800 text-emerald-400 hover:bg-emerald-950/50",
    yellow: "border-yellow-800 text-yellow-400 hover:bg-yellow-950/50",
    red: "border-red-800 text-red-400 hover:bg-red-950/50",
    purple: "border-purple-800 text-purple-400 hover:bg-purple-950/50",
  };
  return (
    <button
      onClick={onClick}
      className={`rounded-lg border px-3 py-1.5 text-xs transition ${colors[color]}`}
    >
      {label}
    </button>
  );
}
