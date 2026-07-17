"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listAttackPaths,
  computeAttackPath,
  pathConfidenceColor,
  pathStatusColor,
  type AttackPath,
} from "@/lib/attackPathsApi";
import { listPlatformOrganizations, type PlatformOrganization } from "@/lib/platform";

export default function AttackPathsPage() {
  const [orgs, setOrgs] = useState<PlatformOrganization[]>([]);
  const [orgId, setOrgId] = useState("");
  const [paths, setPaths] = useState<AttackPath[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Compute workflow
  const [seedIndicatorId, setSeedIndicatorId] = useState("");
  const [computing, setComputing] = useState(false);
  const [computeError, setComputeError] = useState("");
  const [computeResult, setComputeResult] = useState<AttackPath | null>(null);

  useEffect(() => {
    listPlatformOrganizations()
      .then(setOrgs)
      .catch(() => {});
  }, []);

  function loadPaths() {
    if (!orgId) return;
    setPaths(null);
    setLoadError("");
    listAttackPaths({
      organization_id: orgId,
      status: statusFilter || undefined,
      limit: 50,
    })
      .then(setPaths)
      .catch(() => setLoadError("Failed to load attack paths."));
  }

  useEffect(() => { loadPaths(); }, [orgId, statusFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  async function doCompute() {
    if (!orgId || !seedIndicatorId.trim()) return;
    setComputing(true);
    setComputeError("");
    setComputeResult(null);
    try {
      const path = await computeAttackPath({ organization_id: orgId, seed_indicator_id: seedIndicatorId.trim() });
      setComputeResult(path);
      loadPaths();
    } catch {
      setComputeError("Failed to compute attack path — check seed indicator ID and org permissions.");
    } finally {
      setComputing(false);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Attack Paths</h1>
      <p className="mt-1 text-sm text-gray-400">
        Compute and investigate multi-step attack paths from fused threat intelligence.
      </p>

      {/* Org Selector */}
      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={orgId}
          onChange={(e) => setOrgId(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-purple-600"
        >
          <option value="">Select organization…</option>
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>
      </div>

      {orgId && (
        <>
          {/* Compute Workflow */}
          <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
            <h2 className="text-sm font-medium text-gray-300">Compute New Attack Path</h2>
            <p className="mt-1 text-xs text-gray-600">
              Provide a seed fused indicator ID to trace attack paths from that root.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <input
                type="text"
                placeholder="Seed indicator UUID…"
                value={seedIndicatorId}
                onChange={(e) => setSeedIndicatorId(e.target.value)}
                className="min-w-[280px] rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-purple-600"
              />
              <button
                onClick={doCompute}
                disabled={computing || !seedIndicatorId.trim()}
                className="rounded-lg bg-purple-700 px-4 py-2 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
              >
                {computing ? "Computing…" : "Compute Path"}
              </button>
            </div>
            {computeError && (
              <div className="mt-2 text-xs text-red-400">{computeError}</div>
            )}
            {computeResult && (
              <div className="mt-2 rounded-lg border border-emerald-800 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-300">
                Path computed — {computeResult.step_count} steps, confidence:{" "}
                {computeResult.path_confidence}.{" "}
                <Link
                  href={`/platform/threat-intel/attack-paths/${computeResult.id}?org=${orgId}`}
                  className="underline hover:text-emerald-200"
                >
                  View →
                </Link>
              </div>
            )}
          </div>

          {/* Filters */}
          <div className="mt-6 flex gap-2">
            {["", "active", "contained", "historical"].map((s) => (
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

          {/* Path List */}
          {loadError ? (
            <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
              {loadError}
            </div>
          ) : !paths ? (
            <div className="mt-6 text-sm text-gray-500">Loading…</div>
          ) : paths.length === 0 ? (
            <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
              No attack paths found. Compute one above.
            </div>
          ) : (
            <div className="mt-4 space-y-2">
              {paths.map((p) => (
                <div key={p.id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <Link
                        href={`/platform/threat-intel/attack-paths/${p.id}?org=${orgId}`}
                        className="font-medium text-white hover:text-purple-300"
                      >
                        Path {p.id.slice(0, 8)}…
                      </Link>
                      <div className="mt-0.5 text-xs text-gray-500">
                        Root: <span className="font-mono text-gray-400">{p.root_canonical_key}</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <span className={`rounded border px-2 py-0.5 text-xs font-medium ${pathStatusColor(p.status)}`}>
                        {p.status}
                      </span>
                      <span className={`rounded border px-2 py-0.5 text-xs font-medium ${pathConfidenceColor(p.path_confidence)}`}>
                        {p.path_confidence}
                      </span>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-4 text-xs text-gray-500">
                    <span>{p.step_count} steps</span>
                    <span>{p.evidence_count} evidence items</span>
                    <span>exposure {p.max_exposure_score.toFixed(2)}</span>
                    {p.technique_coverage.length > 0 && (
                      <span>{p.technique_coverage.slice(0, 3).join(", ")}{p.technique_coverage.length > 3 ? ` +${p.technique_coverage.length - 3}` : ""}</span>
                    )}
                  </div>
                  <div className="mt-2">
                    <Link
                      href={`/platform/threat-intel/attack-paths/${p.id}?org=${orgId}`}
                      className="text-xs text-purple-400 hover:underline"
                    >
                      Investigate →
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
