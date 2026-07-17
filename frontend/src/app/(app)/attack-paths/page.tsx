"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { listAttackPaths, type AttackPathSummary } from "@/lib/threatIntel";
import { ApiError } from "@/lib/api";

export default function AttackPathsPage() {
  const [paths, setPaths] = useState<AttackPathSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const rows = await listAttackPaths(50);
        if (!cancelled) setPaths(rows);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof ApiError ? e.message : "Failed to load attack paths");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-xl font-bold text-white">Attack Paths</h1>
        <p className="mt-1 text-sm text-gray-400">
          Evidence-backed ATT&amp;CK paths computed from fused threat intelligence.
          Inferred hops are gated; no fabricated narrative steps.
        </p>
      </div>

      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {error && (
        <div className="rounded border border-red-800 bg-red-900/20 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {!loading && !error && paths.length === 0 && (
        <p className="text-sm text-gray-500">
          No attack paths yet. Compute from an investigation or via sync + fusion.
        </p>
      )}

      <div className="divide-y divide-gray-800 rounded-lg border border-gray-800">
        {paths.map((p) => (
          <Link
            key={p.id}
            href={`/attack-paths/${p.id}`}
            className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-gray-900/60"
          >
            <div>
              <div className="text-sm font-medium text-gray-100">
                {p.root_canonical_key}
              </div>
              <div className="mt-0.5 text-xs text-gray-500">
                {p.step_count} steps · {p.technique_coverage.length} techniques ·{" "}
                exposure {p.max_exposure_score.toFixed(1)}
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="rounded border border-gray-700 px-2 py-0.5 text-gray-300">
                {p.path_confidence}
              </span>
              <span className="rounded border border-gray-700 px-2 py-0.5 uppercase text-gray-400">
                {p.status}
              </span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
