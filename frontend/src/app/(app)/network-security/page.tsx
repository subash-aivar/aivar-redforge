"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  activatePolicy,
  createMonitoringPolicy,
  disablePolicy,
  getInventory,
  listMonitoringPolicies,
  pausePolicy,
  resumePolicy,
  runNow,
  type NetworkInventoryEntry,
  type NetworkMonitoringPolicy,
} from "@/lib/networkSecurity";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-white">{value}</p>
    </div>
  );
}

export default function NetworkSecurityPage() {
  const [inventory, setInventory] = useState<NetworkInventoryEntry[] | null>(null);
  const [policies, setPolicies] = useState<NetworkMonitoringPolicy[] | null>(null);
  const [error, setError] = useState("");
  const [newTargetAssetId, setNewTargetAssetId] = useState("");
  const [creating, setCreating] = useState(false);
  const [actionError, setActionError] = useState("");

  async function refresh() {
    try {
      const [inv, pol] = await Promise.all([getInventory(), listMonitoringPolicies()]);
      setInventory(inv);
      setPolicies(pol);
    } catch {
      setError("UNAVAILABLE — failed to load network security data.");
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleCreatePolicy() {
    if (!newTargetAssetId.trim()) return;
    setCreating(true);
    setActionError("");
    try {
      await createMonitoringPolicy({ target_asset_id: newTargetAssetId.trim() });
      setNewTargetAssetId("");
      await refresh();
    } catch {
      setActionError("Failed to create monitoring policy — target must be an existing NETWORK or IP_ADDRESS asset.");
    } finally {
      setCreating(false);
    }
  }

  async function handlePolicyAction(
    action: (id: string) => Promise<NetworkMonitoringPolicy>,
    policyId: string
  ) {
    setActionError("");
    try {
      await action(policyId);
      await refresh();
    } catch {
      setActionError("Action failed.");
    }
  }

  async function handleRunNow(policyId: string) {
    setActionError("");
    try {
      await runNow(policyId);
      await refresh();
    } catch {
      setActionError("Run failed.");
    }
  }

  const monitoredCount = inventory?.filter((i) => i.monitoring_status === "monitored").length ?? 0;
  const conditionCount = inventory?.reduce((sum, i) => sum + i.active_condition_count, 0) ?? 0;

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Network Security</h1>
      <p className="mt-1 text-sm text-gray-400">
        Continuous, authorized network validation over your organization&apos;s
        own canonical network/IP assets. Every active probe is gated by a
        fresh M10 authorization check — this page never scans anything
        without an explicit, approved scope.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : (
        <>
          <div className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="IP / Host Assets" value={inventory?.length ?? "—"} />
            <Stat label="Monitored" value={monitoredCount} />
            <Stat label="Active Conditions" value={conditionCount} />
            <Stat label="Monitoring Policies" value={policies?.length ?? "—"} />
          </div>

          <h2 className="mt-8 text-lg font-semibold text-white">Network Inventory</h2>
          {inventory === null ? (
            <div className="mt-4 text-gray-400">Loading…</div>
          ) : inventory.length === 0 ? (
            <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
              <p className="text-gray-400">No network assets observed yet.</p>
              <p className="mt-2 text-sm text-gray-500">
                Create a NETWORK or IP_ADDRESS asset, obtain an M10
                authorization scoped to it, then create a monitoring policy
                below.
              </p>
            </div>
          ) : (
            <div className="mt-4 overflow-x-auto rounded-xl border border-gray-800">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-left text-xs text-gray-500">
                  <tr>
                    <th className="px-4 py-2">Address</th>
                    <th className="px-4 py-2">Classification</th>
                    <th className="px-4 py-2">Observed Services</th>
                    <th className="px-4 py-2">Conditions</th>
                    <th className="px-4 py-2">Last Observed</th>
                    <th className="px-4 py-2">Monitoring</th>
                  </tr>
                </thead>
                <tbody>
                  {inventory.map((entry) => (
                    <tr key={entry.asset_id} className="border-t border-gray-800 hover:bg-gray-900">
                      <td className="px-4 py-2">
                        <Link
                          href={`/network-security/assets/${entry.asset_id}`}
                          className="font-mono text-blue-400 hover:underline"
                        >
                          {entry.address}
                        </Link>
                      </td>
                      <td className="px-4 py-2 text-gray-400">{entry.address_classification}</td>
                      <td className="px-4 py-2 text-gray-400">
                        {entry.observed_services.length > 0
                          ? entry.observed_services.join(", ")
                          : "—"}
                      </td>
                      <td className="px-4 py-2 text-gray-400">{entry.active_condition_count}</td>
                      <td className="px-4 py-2 text-gray-600">{entry.last_observed_at}</td>
                      <td className="px-4 py-2 text-gray-400">{entry.monitoring_status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2 className="mt-8 text-lg font-semibold text-white">Continuous Monitoring Policies</h2>
          <div className="mt-3 flex gap-2">
            <input
              value={newTargetAssetId}
              onChange={(e) => setNewTargetAssetId(e.target.value)}
              placeholder="Authorized NETWORK/IP_ADDRESS asset id"
              className="w-96 rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-200"
            />
            <button
              onClick={handleCreatePolicy}
              disabled={creating}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-50"
            >
              Create Policy
            </button>
          </div>
          {actionError && <p className="mt-2 text-sm text-red-400">{actionError}</p>}

          {policies === null ? (
            <div className="mt-4 text-gray-400">Loading…</div>
          ) : policies.length === 0 ? (
            <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-400">
              No monitoring policies yet.
            </div>
          ) : (
            <div className="mt-4 overflow-x-auto rounded-xl border border-gray-800">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-left text-xs text-gray-500">
                  <tr>
                    <th className="px-4 py-2">Target Asset</th>
                    <th className="px-4 py-2">Profile</th>
                    <th className="px-4 py-2">Cadence</th>
                    <th className="px-4 py-2">Lifecycle</th>
                    <th className="px-4 py-2">Next Due</th>
                    <th className="px-4 py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.id} className="border-t border-gray-800 hover:bg-gray-900">
                      <td className="px-4 py-2 font-mono text-xs text-gray-300">{p.target_asset_id}</td>
                      <td className="px-4 py-2 text-gray-400">{p.profile}</td>
                      <td className="px-4 py-2 text-gray-400">{p.cadence}</td>
                      <td className="px-4 py-2 text-gray-400">{p.lifecycle}</td>
                      <td className="px-4 py-2 text-gray-600">{p.next_due_at ?? "—"}</td>
                      <td className="px-4 py-2">
                        <div className="flex gap-2">
                          {p.lifecycle === "draft" && (
                            <button
                              onClick={() => handlePolicyAction(activatePolicy, p.id)}
                              className="text-xs text-blue-400 hover:underline"
                            >
                              Activate
                            </button>
                          )}
                          {p.lifecycle === "active" && (
                            <button
                              onClick={() => handlePolicyAction(pausePolicy, p.id)}
                              className="text-xs text-yellow-400 hover:underline"
                            >
                              Pause
                            </button>
                          )}
                          {p.lifecycle === "paused" && (
                            <button
                              onClick={() => handlePolicyAction(resumePolicy, p.id)}
                              className="text-xs text-blue-400 hover:underline"
                            >
                              Resume
                            </button>
                          )}
                          {p.lifecycle !== "disabled" && (
                            <button
                              onClick={() => handlePolicyAction(disablePolicy, p.id)}
                              className="text-xs text-red-400 hover:underline"
                            >
                              Disable
                            </button>
                          )}
                          {p.lifecycle !== "disabled" && (
                            <button
                              onClick={() => handleRunNow(p.id)}
                              className="text-xs text-green-400 hover:underline"
                            >
                              Run Now
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <p className="mt-8 text-xs text-gray-600">
            Active network validation telemetry for a run appears in{" "}
            <Link href="/security-operations" className="text-blue-400 hover:underline">
              Security Operations
            </Link>
            .
          </p>
        </>
      )}
    </div>
  );
}
