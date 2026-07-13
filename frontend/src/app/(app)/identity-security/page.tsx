"use client";

import { useEffect, useState } from "react";
import { listSecurityObservations, type SecurityObservation } from "@/lib/directorySecurity";

export default function IdentitySecurityPage() {
  const [observations, setObservations] = useState<SecurityObservation[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listSecurityObservations()
      .then(setObservations)
      .catch(() => setError("UNAVAILABLE — failed to load identity security observations."));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Identity Security</h1>
      <p className="mt-1 text-sm text-gray-400">
        Deterministic security observations over canonical directory identity
        state — exposure context, not confirmed vulnerabilities or compromise.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : observations === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : observations.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No security observations.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {observations.map((o, i) => (
            <div key={i} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <span className="rounded bg-amber-950 px-2 py-0.5 font-mono text-xs text-amber-400">
                {o.rule_id}
              </span>
              <div className="mt-2 text-sm font-medium text-gray-200">{o.title}</div>
              <div className="mt-1 text-sm text-gray-400">{o.summary}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
