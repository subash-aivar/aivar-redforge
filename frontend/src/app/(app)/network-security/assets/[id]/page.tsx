"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { getAssetDetail, type NetworkAssetDetail } from "@/lib/networkSecurity";

export default function NetworkAssetDetailPage() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<NetworkAssetDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!params?.id) return;
    getAssetDetail(params.id)
      .then(setDetail)
      .catch(() => setError("UNAVAILABLE — failed to load asset detail."));
  }, [params?.id]);

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (detail === null) {
    return <div className="text-gray-400">Loading…</div>;
  }

  return (
    <div>
      <h1 className="text-2xl font-bold font-mono text-white">{detail.address}</h1>
      <p className="mt-1 text-sm text-gray-400">
        {detail.address_classification} · first observed {detail.first_observed_at} · last
        observed {detail.last_observed_at}
      </p>

      <h2 className="mt-8 text-lg font-semibold text-white">Services</h2>
      {detail.services.length === 0 ? (
        <p className="mt-2 text-sm text-gray-500">No services observed.</p>
      ) : (
        <div className="mt-3 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">External ID</th>
                <th className="px-4 py-2">Metadata</th>
              </tr>
            </thead>
            <tbody>
              {detail.services.map((s, i) => (
                <tr key={i} className="border-t border-gray-800">
                  <td className="px-4 py-2 text-gray-200">{s.name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-500">{s.external_id}</td>
                  <td className="px-4 py-2 text-xs text-gray-600">{s.metadata}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="mt-8 text-lg font-semibold text-white">Security Conditions</h2>
      {detail.active_conditions.length === 0 ? (
        <p className="mt-2 text-sm text-gray-500">No active conditions.</p>
      ) : (
        <div className="mt-3 space-y-3">
          {detail.active_conditions.map((c, i) => (
            <div key={i} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
              <p className="text-sm font-semibold text-white">
                {c.title} <span className="ml-2 text-xs uppercase text-yellow-400">{c.severity}</span>
              </p>
              <p className="mt-1 text-sm text-gray-400">{c.summary}</p>
            </div>
          ))}
        </div>
      )}

      <h2 className="mt-8 text-lg font-semibold text-white">Correlations</h2>
      {detail.active_correlations.length === 0 ? (
        <p className="mt-2 text-sm text-gray-500">No active correlations.</p>
      ) : (
        <div className="mt-3 space-y-3">
          {detail.active_correlations.map((c, i) => (
            <div key={i} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
              <p className="text-sm font-semibold text-white">{c.title}</p>
              <p className="mt-1 text-sm text-gray-400">{c.summary}</p>
            </div>
          ))}
        </div>
      )}

      <h2 className="mt-8 text-lg font-semibold text-white">Monitoring</h2>
      <p className="mt-2 text-sm text-gray-400">
        {detail.monitoring_policy_id
          ? `Policy ${detail.monitoring_policy_id} — ${detail.monitoring_lifecycle}`
          : "Not monitored."}
      </p>
    </div>
  );
}
