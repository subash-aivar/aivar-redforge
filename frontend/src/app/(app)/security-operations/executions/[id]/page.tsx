"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  getExecutionDetail,
  type ExecutionTelemetryDetail,
} from "@/lib/securityOperations";
import { formatDateTime, phaseLabel } from "../../security-operations-helpers";

const NON_TERMINAL_STATES = new Set(["pending", "policy_checking", "authorized", "running"]);

export default function ExecutionTelemetryDetailPage() {
  const params = useParams<{ id: string }>();
  const executionId = params.id;
  const [detail, setDetail] = useState<ExecutionTelemetryDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    getExecutionDetail(executionId)
      .then((d) => {
        setDetail(d);
        setError("");
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "UNAVAILABLE — failed to load.");
      });
  }, [executionId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!detail || !NON_TERMINAL_STATES.has(detail.summary.state)) return;
    const interval = setInterval(load, 2000);
    return () => clearInterval(interval);
  }, [detail, load]);

  return (
    <div>
      <Link
        href="/security-operations"
        className="text-xs text-gray-500 hover:text-gray-300"
      >
        ← Back to Security Operations
      </Link>

      {error ? (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
          {error}
        </div>
      ) : null}

      {detail ? (
        <>
          <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-5">
            <div className="flex items-center justify-between">
              <h1 className="text-xl font-bold text-white">{detail.summary.target_id}</h1>
              <span className="rounded border border-gray-700 bg-gray-800 px-2 py-0.5 text-xs uppercase text-gray-300">
                {detail.summary.state}
              </span>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-3 text-xs text-gray-400 sm:grid-cols-4">
              <div>
                <div className="text-gray-500">Execution ID</div>
                <div className="text-gray-300">{detail.summary.id}</div>
              </div>
              <div>
                <div className="text-gray-500">Trigger</div>
                <div className="text-gray-300">{detail.summary.trigger.toUpperCase()}</div>
              </div>
              <div>
                <div className="text-gray-500">Profile</div>
                <div className="text-gray-300">{detail.summary.profile}</div>
              </div>
              {detail.summary.continuous_policy_id ? (
                <div>
                  <div className="text-gray-500">Policy</div>
                  <div className="text-gray-300">{detail.summary.continuous_policy_id}</div>
                </div>
              ) : null}
              <div>
                <div className="text-gray-500">Started</div>
                <div className="text-gray-300">{formatDateTime(detail.summary.started_at)}</div>
              </div>
              <div>
                <div className="text-gray-500">Completed</div>
                <div className="text-gray-300">{formatDateTime(detail.summary.completed_at)}</div>
              </div>
            </div>
          </div>

          <div className="mt-4 rounded-xl border border-blue-800 bg-blue-950/40 p-4">
            <div className="text-xs uppercase tracking-wide text-blue-400">Current phase</div>
            <div className="mt-1 text-lg font-semibold text-white" data-testid="current-phase">
              {phaseLabel(detail.summary.phase)}
            </div>
          </div>

          <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-5">
            <h2 className="text-sm font-semibold text-white">Telemetry Timeline</h2>
            <div className="mt-3">
              {detail.timeline.length === 0 ? (
                <p className="py-6 text-center text-xs text-gray-500">No events yet.</p>
              ) : (
                detail.timeline.map((entry, idx) => (
                  <div
                    key={`${entry.event_type}-${idx}`}
                    className="flex items-start gap-3 border-b border-gray-800 py-2 last:border-0"
                  >
                    <span className="mt-0.5 w-40 shrink-0 text-[10px] uppercase tracking-wide text-gray-500">
                      {phaseLabel(entry.phase)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-gray-200">{entry.title}</div>
                      <div className="text-xs text-gray-500">
                        {formatDateTime(entry.occurred_at)}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {detail.result_summary ? (
            <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-5">
              <h2 className="text-sm font-semibold text-white">Result Summary</h2>
              <p className="mt-2 text-sm text-gray-300">{detail.result_summary}</p>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
