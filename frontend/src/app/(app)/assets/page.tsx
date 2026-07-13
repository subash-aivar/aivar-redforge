"use client";

import { useEffect, useState } from "react";
import {
  getAsset,
  getAssetRelationships,
  listAssets,
  type Asset,
  type AssetRelationship,
} from "@/lib/assets";

const KNOWN_KINDS = new Set([
  "ai_application", "ai_agent", "ai_model", "ai_provider", "rag_system",
  "mcp_server", "prompt_template", "tool_definition", "memory_store",
  "knowledge_base", "embedding_model", "vector_database", "ai_endpoint",
  "application", "url", "host", "ip_address", "cloud_resource",
]);

function canonicalKind(kind: string): string {
  return KNOWN_KINDS.has(kind) ? kind : "UNKNOWN";
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Asset | null>(null);
  const [relationships, setRelationships] = useState<AssetRelationship[] | null>(null);
  const [detailError, setDetailError] = useState("");

  useEffect(() => {
    listAssets()
      .then(setAssets)
      .catch(() => setError("UNAVAILABLE — failed to load asset inventory."));
  }, []);

  async function openDetail(id: string) {
    setSelectedId(id);
    setDetail(null);
    setRelationships(null);
    setDetailError("");
    try {
      const [a, rels] = await Promise.all([getAsset(id), getAssetRelationships(id)]);
      setDetail(a);
      setRelationships(rels);
    } catch {
      setDetailError("UNAVAILABLE — failed to load asset detail.");
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
      <p className="mt-1 text-sm text-gray-400">
        Canonical, tenant-owned assets resolved from discovery. Assets are
        inventory identity only — discovery never grants campaign execution
        authorization.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : assets === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : assets.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
          <p className="text-gray-400">No assets yet.</p>
          <p className="mt-2 text-sm text-gray-500">
            Register a connector and run discovery, or create an AI target —
            targets automatically resolve a canonical asset.
          </p>
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Kind</th>
                <th className="px-4 py-2">Lifecycle</th>
                <th className="px-4 py-2">Source</th>
                <th className="px-4 py-2">Last Observed</th>
                <th className="px-4 py-2">Relationships</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => openDetail(a.id)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{a.name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-blue-400">
                    {canonicalKind(a.asset_type)}
                  </td>
                  <td className="px-4 py-2 text-gray-400">{a.lifecycle_stage}</td>
                  <td className="px-4 py-2 text-gray-500">{a.discovery_source}</td>
                  <td className="px-4 py-2 text-gray-600">
                    {new Date(a.last_observed_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-gray-500">{a.relationship_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedId && (
        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Asset Detail</h2>
            <button
              onClick={() => setSelectedId(null)}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Close
            </button>
          </div>

          {detailError ? (
            <div className="mt-3 text-sm text-red-400">{detailError}</div>
          ) : detail === null ? (
            <div className="mt-3 text-sm text-gray-500">Loading…</div>
          ) : (
            <div className="mt-3">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Stat label="Kind" value={canonicalKind(detail.asset_type)} />
                <Stat label="Lifecycle" value={detail.lifecycle_stage} />
                <Stat label="Health" value={detail.health_status} />
                <Stat label="Source" value={detail.discovery_source} />
              </div>
              <div className="mt-3 text-xs text-gray-600 font-mono break-all">
                external_id: {detail.external_id}
              </div>
              {detail.associated_target_id && (
                <div className="mt-1 text-xs text-gray-500">
                  Associated AI target:{" "}
                  <span className="font-mono text-gray-300">
                    {detail.associated_target_id}
                  </span>
                </div>
              )}
              <div className="mt-1 text-xs text-gray-600">
                First observed {new Date(detail.first_observed_at).toLocaleString()} · Last
                observed {new Date(detail.last_observed_at).toLocaleString()}
              </div>

              <div className="mt-4">
                <div className="mb-2 text-sm font-medium text-gray-400">
                  Relationships ({relationships?.length ?? 0})
                </div>
                {relationships === null ? (
                  <div className="text-xs text-gray-500">Loading…</div>
                ) : relationships.length === 0 ? (
                  <div className="text-xs text-gray-600">No relationships recorded.</div>
                ) : (
                  <div className="space-y-2">
                    {relationships.map((r) => (
                      <div
                        key={r.relationship_id}
                        className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs"
                      >
                        <span className="font-mono text-blue-400">{r.relationship_type}</span>
                        <span className="text-gray-600"> → </span>
                        <span className="font-mono text-gray-400">
                          {r.target_asset_id.slice(0, 12)}…
                        </span>
                        {r.label && <span className="ml-2 text-gray-500">({r.label})</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="text-sm font-bold text-white truncate">{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}
