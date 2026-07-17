"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listFeeds,
  activateFeed,
  pauseFeed,
  disableFeed,
  triggerFeedSync,
  feedStatusColor,
  formatInterval,
  SOURCE_KIND_LABELS,
  type Feed,
} from "@/lib/feedSync";

export default function FeedManagementPage() {
  const [feeds, setFeeds] = useState<Feed[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [actionError, setActionError] = useState("");

  function load() {
    setFeeds(null);
    setError("");
    listFeeds({ status: statusFilter || undefined, limit: 50 })
      .then((r) => { setFeeds(r.items); setTotal(r.total); })
      .catch(() => setError("Failed to load feeds."));
  }

  useEffect(() => { load(); }, [statusFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  async function doAction(feedId: string, action: "activate" | "pause" | "disable" | "sync") {
    setActionError("");
    try {
      if (action === "activate") await activateFeed(feedId);
      else if (action === "pause") await pauseFeed(feedId);
      else if (action === "disable") await disableFeed(feedId);
      else await triggerFeedSync(feedId);
      load();
    } catch {
      setActionError(`Action '${action}' failed — check permissions or feed state.`);
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Feed Management</h1>
          <p className="mt-1 text-sm text-gray-400">
            Register, configure, and monitor threat intelligence feed connectors.
          </p>
        </div>
        <Link
          href="/platform/threat-intel/feeds/new"
          className="rounded-lg bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-600"
        >
          Register Feed
        </Link>
      </div>

      <div className="mt-4 flex gap-2">
        {["", "active", "paused", "disabled", "error"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setStatusFilter(s)}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
              statusFilter === s
                ? "border-purple-700 bg-purple-950/60 text-purple-300"
                : "border-gray-700 text-gray-500 hover:text-gray-300"
            }`}
          >
            {s || "All"}
          </button>
        ))}
      </div>

      {actionError && (
        <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : !feeds ? (
        <div className="mt-8 text-sm text-gray-500">Loading…</div>
      ) : feeds.length === 0 ? (
        <div className="mt-6 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
          No feeds found.{" "}
          <Link href="/platform/threat-intel/feeds/new" className="text-purple-400 hover:underline">
            Register a feed.
          </Link>
        </div>
      ) : (
        <>
          <div className="mt-1 text-xs text-gray-600">{total} total</div>
          <div className="mt-3 space-y-2">
            {feeds.map((f) => (
              <FeedRow key={f.id} feed={f} onAction={doAction} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FeedRow({
  feed,
  onAction,
}: {
  feed: Feed;
  onAction: (id: string, action: "activate" | "pause" | "disable" | "sync") => void;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <Link
            href={`/platform/threat-intel/feeds/${feed.id}`}
            className="font-medium text-white hover:text-purple-300"
          >
            {feed.display_name}
          </Link>
          <div className="mt-0.5 flex flex-wrap gap-2 text-xs text-gray-500">
            <span className="font-mono">{feed.feed_key}</span>
            <span>{SOURCE_KIND_LABELS[feed.source_kind] ?? feed.source_kind}</span>
            <span>every {formatInterval(feed.schedule_interval_seconds)}</span>
            {feed.consecutive_failure_count > 0 && (
              <span className="text-red-400">{feed.consecutive_failure_count} consecutive failures</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`rounded border px-2 py-0.5 text-xs font-medium ${feedStatusColor(feed.status)}`}
          >
            {feed.status}
          </span>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
        <span>
          Last sync:{" "}
          {feed.last_sync_completed_at
            ? new Date(feed.last_sync_completed_at).toLocaleString()
            : "never"}
        </span>
        {feed.last_sync_status && (
          <span
            className={
              feed.last_sync_status === "succeeded"
                ? "text-emerald-400"
                : feed.last_sync_status === "failed"
                ? "text-red-400"
                : "text-gray-500"
            }
          >
            {feed.last_sync_status}
          </span>
        )}
      </div>

      <div className="mt-3 flex gap-2">
        {feed.status !== "active" && (
          <ActionButton label="Activate" onClick={() => onAction(feed.id, "activate")} color="emerald" />
        )}
        {feed.status === "active" && (
          <ActionButton label="Pause" onClick={() => onAction(feed.id, "pause")} color="yellow" />
        )}
        {feed.status !== "disabled" && (
          <ActionButton label="Disable" onClick={() => onAction(feed.id, "disable")} color="red" />
        )}
        <ActionButton label="Sync Now" onClick={() => onAction(feed.id, "sync")} color="purple" />
        <Link
          href={`/platform/threat-intel/feeds/${feed.id}`}
          className="rounded-lg border border-gray-700 px-3 py-1 text-xs text-gray-400 hover:border-gray-600 hover:text-gray-200"
        >
          Details →
        </Link>
      </div>
    </div>
  );
}

function ActionButton({
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
      className={`rounded-lg border px-3 py-1 text-xs transition ${colors[color]}`}
    >
      {label}
    </button>
  );
}
