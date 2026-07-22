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
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  getExposureProfile,
  queryExposureScope,
  suppressRecord,
  getThreatTargeting,
  type ExposureProfile,
  type ExposureScopeResult,
  type ThreatTargeting,
} from "@/lib/exposure";

export default function ExposureDashboardPage() {
  const profile = useAsync(() => getExposureProfile(), []);
  const scope = useAsync(
    () => queryExposureScope({ max_assets: 50, min_exposure_score: 0.0 }),
    []
  );
  const threats = useAsync(() => getThreatTargeting(), []);

  return (
    <>
      <PageHeader
        title="Exposure Intelligence"
        subtitle="Unified exposure scoring, threat-context amplification, and risk prioritization"
        actions={
          <button
            type="button"
            onClick={() => { profile.reload(); scope.reload(); threats.reload(); }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      {/* KPI tiles */}
      <AsyncContent state={profile}>
        {(p) => (
          <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
            <KpiTile label="Total Assets" value={p.total_assets} />
            <KpiTile label="Avg Score" value={p.avg_score.toFixed(1)} />
            <KpiTile label="Critical" value={p.critical_count} tone="danger" />
            <KpiTile label="High" value={p.high_count} tone="danger" />
            <KpiTile label="Medium" value={p.medium_count} tone="warning" />
            <KpiTile label="Low" value={p.low_count} tone="ok" />
          </div>
        )}
      </AsyncContent>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Exposure scope: top-exposed assets */}
        <div className="lg:col-span-2">
          <Panel title="Top Exposed Assets">
            <AsyncContent state={scope}>
              {(s) =>
                s.assets.length === 0 ? (
                  <p className="p-4 text-sm text-gray-500">
                    No exposure data. Ingest vulnerability, cloud, or AI risk signals to populate.
                  </p>
                ) : (
                  <div className="divide-y divide-gray-800">
                    {s.assets.map((a) => (
                      <div
                        key={a.asset_ref_id}
                        className="flex items-center justify-between px-4 py-3"
                      >
                        <div>
                          <span className="font-mono text-xs text-gray-400">
                            {a.asset_ref_id.slice(0, 12)}…
                          </span>
                          <span className="ml-3 rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400">
                            {a.asset_kind || "UNKNOWN"}
                          </span>
                        </div>
                        <div className="flex items-center gap-4">
                          <span className="text-xs text-gray-500">
                            {a.active_records} signals
                          </span>
                          <ScoreBadge score={a.score} />
                        </div>
                      </div>
                    ))}
                  </div>
                )
              }
            </AsyncContent>
          </Panel>
        </div>

        {/* Threat targeting panel */}
        <Panel title="Active Threat Targeting">
          <AsyncContent state={threats}>
            {(t) =>
              t.actors.length === 0 ? (
                <p className="p-4 text-sm text-gray-500">
                  No active threat actor targeting data.
                </p>
              ) : (
                <div className="divide-y divide-gray-800">
                  {t.actors.map((actor, i) => (
                    <div key={i} className="px-4 py-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-gray-200">
                          {actor.threat_actor_ref}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                            actor.targeting_confidence === "High"
                              ? "bg-red-950 text-red-400"
                              : actor.targeting_confidence === "Medium"
                                ? "bg-amber-950 text-amber-400"
                                : "bg-gray-800 text-gray-400"
                          }`}
                        >
                          {actor.targeting_confidence}
                        </span>
                      </div>
                      {actor.targeted_cve_ids.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {actor.targeted_cve_ids.slice(0, 4).map((cve) => (
                            <span
                              key={cve}
                              className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400"
                            >
                              {cve}
                            </span>
                          ))}
                          {actor.targeted_cve_ids.length > 4 && (
                            <span className="text-[10px] text-gray-600">
                              +{actor.targeted_cve_ids.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                      {actor.targeted_techniques.length > 0 && (
                        <div className="mt-1 text-[10px] text-gray-500">
                          Techniques: {actor.targeted_techniques.slice(0, 3).join(", ")}
                          {actor.targeted_techniques.length > 3 && " …"}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )
            }
          </AsyncContent>
        </Panel>
      </div>
    </>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const tone =
    score >= 8.0
      ? "bg-red-950 text-red-400 border-red-800"
      : score >= 6.0
        ? "bg-orange-950 text-orange-400 border-orange-800"
        : score >= 4.0
          ? "bg-amber-950 text-amber-400 border-amber-800"
          : "bg-gray-800 text-gray-400 border-gray-700";
  return (
    <span className={`inline-flex min-w-[3rem] justify-center rounded border px-2 py-0.5 text-xs font-bold ${tone}`}>
      {score.toFixed(1)}
    </span>
  );
}
