"use client";

import { useState } from "react";
import {
  AsyncContent,
  KpiTile,
  PageHeader,
  Panel,
  PostureGauge,
  fmtTime,
  useAsync,
} from "@/components/cc";
import { generateForecast, getLatestForecast, type PostureForecastDTO } from "@/lib/postureForecasting";

/** Exposure scores are on a 0-10 scale (lower = better). Convert to a
 * 0-100 "posture" scale for the gauge (100 - exposure*10) so the visual
 * language matches other posture gauges in the app (higher = healthier). */
function toPostureScore(exposureScore: number): number {
  return Math.max(0, Math.min(100, Math.round(100 - exposureScore * 10)));
}

function bandFor(postureScore: number): string {
  if (postureScore >= 80) return "strong";
  if (postureScore >= 60) return "moderate";
  if (postureScore >= 40) return "at_risk";
  return "critical";
}

export default function PostureForecastingPage() {
  const forecast = useAsync(() => getLatestForecast(), []);
  const [showGenerate, setShowGenerate] = useState(false);

  return (
    <>
      <PageHeader
        title="Posture Forecasting"
        subtitle="30/60/90-day predicted security posture based on remediation velocity and open findings"
        actions={
          <button
            onClick={() => setShowGenerate(true)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
          >
            Generate Forecast
          </button>
        }
      />

      <AsyncContent state={forecast} emptyLabel="No forecast generated yet. Generate one to see predicted posture.">
        {(f) => (
          <>
            <div className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <KpiTile label="Baseline Exposure Score" value={f.baseline_exposure_score.toFixed(1)} />
              <KpiTile label="Generated At" value={fmtTime(f.generated_at)} />
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <Panel title="30-Day Prediction">
                <div className="flex flex-col items-center">
                  <PostureGauge score={toPostureScore(f.predicted_30d)} band={bandFor(toPostureScore(f.predicted_30d))} />
                  <p className="mt-2 text-xs text-gray-500">Predicted exposure: {f.predicted_30d.toFixed(2)}</p>
                </div>
              </Panel>
              <Panel title="60-Day Prediction">
                <div className="flex flex-col items-center">
                  <PostureGauge score={toPostureScore(f.predicted_60d)} band={bandFor(toPostureScore(f.predicted_60d))} />
                  <p className="mt-2 text-xs text-gray-500">Predicted exposure: {f.predicted_60d.toFixed(2)}</p>
                </div>
              </Panel>
              <Panel title="90-Day Prediction">
                <div className="flex flex-col items-center">
                  <PostureGauge score={toPostureScore(f.predicted_90d)} band={bandFor(toPostureScore(f.predicted_90d))} />
                  <p className="mt-2 text-xs text-gray-500">Predicted exposure: {f.predicted_90d.toFixed(2)}</p>
                </div>
              </Panel>
            </div>
          </>
        )}
      </AsyncContent>

      {showGenerate && (
        <GenerateForecastModal
          onClose={() => setShowGenerate(false)}
          onGenerated={() => {
            forecast.reload();
            setShowGenerate(false);
          }}
        />
      )}
    </>
  );
}

function GenerateForecastModal({
  onClose,
  onGenerated,
}: {
  onClose: () => void;
  onGenerated: (f: PostureForecastDTO) => void;
}) {
  const [baseline, setBaseline] = useState(5.0);
  const [velocity, setVelocity] = useState(1.0);
  const [criticalCount, setCriticalCount] = useState(0);
  const [highCount, setHighCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const f = await generateForecast({
        baseline_exposure_score: baseline,
        remediation_velocity_per_day: velocity,
        open_critical_count: criticalCount,
        open_high_count: highCount,
      });
      onGenerated(f);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate forecast");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-sm rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h3 className="mb-3 text-sm font-semibold text-gray-100">Generate Posture Forecast</h3>

        <label className="mb-1 block text-xs text-gray-500">Baseline Exposure Score (0-10)</label>
        <input
          type="number"
          step="0.1"
          min={0}
          max={10}
          value={baseline}
          onChange={(e) => setBaseline(Number(e.target.value))}
          className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />

        <label className="mb-1 block text-xs text-gray-500">Remediation Velocity (per day)</label>
        <input
          type="number"
          step="0.1"
          value={velocity}
          onChange={(e) => setVelocity(Number(e.target.value))}
          className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />

        <label className="mb-1 block text-xs text-gray-500">Open Critical Findings</label>
        <input
          type="number"
          min={0}
          value={criticalCount}
          onChange={(e) => setCriticalCount(Number(e.target.value))}
          className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />

        <label className="mb-1 block text-xs text-gray-500">Open High Findings</label>
        <input
          type="number"
          min={0}
          value={highCount}
          onChange={(e) => setHighCount(Number(e.target.value))}
          className="mb-4 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />

        {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
            Cancel
          </button>
          <button
            disabled={busy}
            onClick={submit}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
          >
            {busy ? "Generating…" : "Generate"}
          </button>
        </div>
      </div>
    </div>
  );
}
