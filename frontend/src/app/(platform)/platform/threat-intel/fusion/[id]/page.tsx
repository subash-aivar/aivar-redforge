"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import {
  getFusedIndicator,
  confidenceColor,
  riskStateColor,
  lifecycleColor,
  type FusedIndicator,
} from "@/lib/fusion";

export default function FusedIndicatorDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [indicator, setIndicator] = useState<FusedIndicator | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getFusedIndicator(id)
      .then(setIndicator)
      .catch(() => setError("Indicator not found or access denied."));
  }, [id]);

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (!indicator) return <div className="text-sm text-gray-500">Loading…</div>;

  return (
    <div>
      <div className="flex items-center gap-2 text-xs text-gray-600">
        <Link href="/platform/threat-intel/fusion" className="hover:text-gray-400">
          ← Fusion Explorer
        </Link>
      </div>

      <h1 className="mt-2 text-2xl font-bold text-white">{indicator.display_name}</h1>
      <div className="mt-1 font-mono text-xs text-gray-500">{indicator.canonical_key}</div>

      <div className="mt-4 flex flex-wrap gap-2">
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${lifecycleColor(indicator.lifecycle)}`}>
          {indicator.lifecycle}
        </span>
        {indicator.confidence && (
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${confidenceColor(indicator.confidence)}`}>
            confidence: {indicator.confidence}
          </span>
        )}
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${riskStateColor(indicator.risk_state)}`}>
          risk: {indicator.risk_state}
        </span>
        <span className="rounded border border-gray-700 bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
          {indicator.source_count} source{indicator.source_count !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <InfoCard label="Type" value={indicator.indicator_type} />
        <InfoCard label="Winner Source" value={indicator.winner_source_system ?? "—"} />
        <InfoCard
          label="Valid From"
          value={new Date(indicator.valid_from).toLocaleString()}
        />
        <InfoCard
          label="Valid Until"
          value={indicator.valid_until ? new Date(indicator.valid_until).toLocaleString() : "Open-ended"}
        />
      </div>

      {Object.keys(indicator.metadata).length > 0 && (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="text-sm font-medium text-gray-300">Metadata</h2>
          <pre className="mt-2 overflow-x-auto text-xs text-gray-500">
            {JSON.stringify(indicator.metadata, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="mt-1 text-sm font-medium text-gray-200">{value}</div>
    </div>
  );
}
