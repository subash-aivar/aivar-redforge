"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { getAttackPath, type AttackPathSummary } from "@/lib/threatIntel";
import { ApiError } from "@/lib/api";

export default function AttackPathDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [path, setPath] = useState<AttackPathSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const row = await getAttackPath(id);
        if (!cancelled) setPath(row);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof ApiError ? e.message : "Failed to load path");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return (
      <div className="p-6">
        <div className="rounded border border-red-800 bg-red-900/20 p-3 text-sm text-red-300">
          {error}
        </div>
        <Link href="/attack-paths" className="mt-4 inline-block text-sm text-gray-400">
          ← Back
        </Link>
      </div>
    );
  }

  if (!path) {
    return <div className="p-6 text-sm text-gray-500">Loading path…</div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <Link href="/attack-paths" className="text-xs text-gray-500 hover:text-gray-300">
          ← Attack Paths
        </Link>
        <h1 className="mt-2 text-xl font-bold text-white">{path.root_canonical_key}</h1>
        <p className="mt-1 text-sm text-gray-400">
          Confidence {path.path_confidence} · {path.step_count} steps · status{" "}
          {path.status}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded border border-gray-800 p-3">
          <div className="text-[10px] uppercase text-gray-500">Exposure</div>
          <div className="text-lg text-white">{path.max_exposure_score.toFixed(2)}</div>
        </div>
        <div className="rounded border border-gray-800 p-3">
          <div className="text-[10px] uppercase text-gray-500">Evidence</div>
          <div className="text-lg text-white">{path.evidence_count}</div>
        </div>
        <div className="rounded border border-gray-800 p-3">
          <div className="text-[10px] uppercase text-gray-500">Techniques</div>
          <div className="text-lg text-white">{path.technique_coverage.length}</div>
        </div>
        <div className="rounded border border-gray-800 p-3">
          <div className="text-[10px] uppercase text-gray-500">Investigation</div>
          <div className="truncate text-sm text-gray-200">
            {path.investigation_id ?? "—"}
          </div>
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold text-gray-200">Technique coverage</h2>
        <div className="flex flex-wrap gap-1.5">
          {path.technique_coverage.map((t) => (
            <span
              key={t}
              className="rounded border border-gray-700 bg-gray-900 px-2 py-0.5 text-xs text-gray-300"
            >
              {t}
            </span>
          ))}
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold text-gray-200">Steps</h2>
        <div className="divide-y divide-gray-800 rounded-lg border border-gray-800">
          {(path.steps ?? []).map((s) => (
            <div key={s.sequence} className="px-4 py-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-gray-100">
                  #{s.sequence} {s.canonical_key}
                </span>
                <span className="text-[10px] uppercase tracking-wide text-gray-500">
                  {s.step_type} · {s.confidence}
                </span>
              </div>
              <div className="mt-1 text-xs text-gray-500">
                {s.technique_id ?? "—"} · {s.kill_chain_phase ?? "no kill-chain"} ·
                exposure {s.exposure_score.toFixed(2)}
              </div>
            </div>
          ))}
          {(path.steps ?? []).length === 0 && (
            <div className="px-4 py-3 text-sm text-gray-500">No steps loaded.</div>
          )}
        </div>
      </div>
    </div>
  );
}
