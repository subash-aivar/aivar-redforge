"use client";

import { useEffect, useState } from "react";
import { getPlatformAudit, type PlatformAuditEntry } from "@/lib/platform";

const ACTION_LABELS: Record<string, string> = {
  "platform.bootstrap_succeeded": "BOOTSTRAP SUPER ADMIN",
  "platform.bootstrap_denied": "BOOTSTRAP DENIED",
  "platform.access_granted": "GRANT PLATFORM ACCESS",
  "platform.access_revoked": "REVOKE PLATFORM ACCESS",
  "platform.access_denied": "ACCESS DENIED",
};

export default function PlatformAuditPage() {
  const [entries, setEntries] = useState<PlatformAuditEntry[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getPlatformAudit()
      .then(setEntries)
      .catch(() => setError("UNAVAILABLE — failed to load platform audit log."));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Platform Security Audit</h1>
      <p className="mt-1 text-sm text-gray-400">
        Append-only record of platform privilege changes — bootstrap, access
        grants, and revocations. This is an application audit log, not a
        cryptographically-immutable ledger.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : entries === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : entries.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 px-4 py-6 text-center text-sm text-gray-500">
          No platform security events recorded yet.
        </div>
      ) : (
        <div className="mt-6 space-y-2">
          {entries.map((e, i) => (
            <div key={i} className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-medium text-purple-300">
                  {ACTION_LABELS[e.action] ?? e.action}
                </span>
                <span
                  className={`text-xs font-medium ${
                    e.outcome === "success" ? "text-green-400" : "text-red-400"
                  }`}
                >
                  {e.outcome.toUpperCase()}
                </span>
              </div>
              <div className="mt-1 grid grid-cols-2 gap-x-4 text-xs text-gray-500 sm:grid-cols-4">
                <div>
                  Actor: <span className="text-gray-400 font-mono">{e.actor_id.slice(0, 12)}…</span>
                </div>
                <div>
                  Target: <span className="text-gray-400 font-mono">{e.target_id.slice(0, 12)}…</span>
                </div>
                {e.role && (
                  <div>
                    Role: <span className="text-gray-400">{e.role}</span>
                  </div>
                )}
                <div>
                  Time:{" "}
                  <span className="text-gray-400">
                    {new Date(e.timestamp).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
