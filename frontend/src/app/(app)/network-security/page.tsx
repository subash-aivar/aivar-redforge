"use client";

import Link from "next/link";
import { useState } from "react";
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
import {
  AsyncContent,
  DataConsole,
  KpiTile,
  Panel,
  PageHeader,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";

export default function NetworkSecurityPage() {
  const inventoryState = useAsync(() => getInventory(), []);
  const policiesState = useAsync(() => listMonitoringPolicies(), []);

  const [newTargetAssetId, setNewTargetAssetId] = useState("");
  const [creating, setCreating] = useState(false);
  const [actionError, setActionError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  function refresh() {
    inventoryState.reload();
    policiesState.reload();
  }

  async function handleCreatePolicy() {
    if (!newTargetAssetId.trim()) return;
    setCreating(true);
    setActionError("");
    try {
      await createMonitoringPolicy({ target_asset_id: newTargetAssetId.trim() });
      setNewTargetAssetId("");
      refresh();
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
    setBusyId(policyId);
    setActionError("");
    try {
      await action(policyId);
      refresh();
    } catch {
      setActionError("Action failed.");
    } finally {
      setBusyId(null);
    }
  }

  async function handleRunNow(policyId: string) {
    setBusyId(policyId);
    setActionError("");
    try {
      await runNow(policyId);
      refresh();
    } catch {
      setActionError("Run failed.");
    } finally {
      setBusyId(null);
    }
  }

  const inventory = inventoryState.data ?? [];
  const policies = policiesState.data ?? [];
  const monitoredCount = inventory.filter((i) => i.monitoring_status === "monitored").length;
  const conditionCount = inventory.reduce((sum, i) => sum + i.active_condition_count, 0);

  const inventoryColumns: ConsoleColumn<NetworkInventoryEntry>[] = [
    {
      key: "address",
      header: "Address",
      render: (entry) => (
        <Link
          href={`/network-security/assets/${entry.asset_id}`}
          className="font-mono text-blue-400 hover:underline"
        >
          {entry.address}
        </Link>
      ),
    },
    {
      key: "classification",
      header: "Classification",
      render: (entry) => <span className="text-gray-400">{entry.address_classification}</span>,
    },
    {
      key: "services",
      header: "Observed Services",
      render: (entry) => (
        <span className="text-gray-400">
          {entry.observed_services.length > 0 ? entry.observed_services.join(", ") : "—"}
        </span>
      ),
    },
    {
      key: "conditions",
      header: "Conditions",
      render: (entry) => <span className="text-gray-400">{entry.active_condition_count}</span>,
    },
    {
      key: "last_observed",
      header: "Last Observed",
      render: (entry) => <span className="text-gray-600">{entry.last_observed_at}</span>,
    },
    {
      key: "monitoring",
      header: "Monitoring",
      render: (entry) => <span className="text-gray-400">{entry.monitoring_status}</span>,
    },
  ];

  const policyColumns: ConsoleColumn<NetworkMonitoringPolicy>[] = [
    {
      key: "target",
      header: "Target Asset",
      render: (p) => <span className="font-mono text-xs text-gray-300">{p.target_asset_id}</span>,
    },
    {
      key: "profile",
      header: "Profile",
      render: (p) => <span className="text-gray-400">{p.profile}</span>,
    },
    {
      key: "cadence",
      header: "Cadence",
      render: (p) => <span className="text-gray-400">{p.cadence}</span>,
    },
    {
      key: "lifecycle",
      header: "Lifecycle",
      render: (p) => (
        <StatusPill status={p.lifecycle === "active" ? "active" : p.lifecycle} />
      ),
    },
    {
      key: "next_due",
      header: "Next Due",
      render: (p) => <span className="text-gray-600">{p.next_due_at ?? "—"}</span>,
    },
    {
      key: "actions",
      header: "Actions",
      render: (p) => (
        <div className="flex gap-2 text-xs" onClick={(e) => e.stopPropagation()}>
          {p.lifecycle === "draft" && (
            <button
              onClick={() => handlePolicyAction(activatePolicy, p.id)}
              disabled={busyId === p.id}
              className="text-blue-400 hover:underline disabled:opacity-50"
            >
              Activate
            </button>
          )}
          {p.lifecycle === "active" && (
            <button
              onClick={() => handlePolicyAction(pausePolicy, p.id)}
              disabled={busyId === p.id}
              className="text-yellow-400 hover:underline disabled:opacity-50"
            >
              Pause
            </button>
          )}
          {p.lifecycle === "paused" && (
            <button
              onClick={() => handlePolicyAction(resumePolicy, p.id)}
              disabled={busyId === p.id}
              className="text-blue-400 hover:underline disabled:opacity-50"
            >
              Resume
            </button>
          )}
          {p.lifecycle !== "disabled" && (
            <button
              onClick={() => handlePolicyAction(disablePolicy, p.id)}
              disabled={busyId === p.id}
              className="text-red-400 hover:underline disabled:opacity-50"
            >
              Disable
            </button>
          )}
          {p.lifecycle !== "disabled" && (
            <button
              onClick={() => handleRunNow(p.id)}
              disabled={busyId === p.id}
              className="text-green-400 hover:underline disabled:opacity-50"
            >
              Run Now
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Network Security"
        subtitle="Continuous, authorized network validation over your organization's own canonical network/IP assets. Every active probe is gated by a fresh M10 authorization check — this page never scans anything without an explicit, approved scope."
        actions={
          <button
            onClick={() => setShowCreateForm((v) => !v)}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:text-white"
          >
            {showCreateForm ? "Hide create policy" : "Create policy"}
          </button>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile label="IP / Host Assets" value={inventory.length} />
        <KpiTile label="Monitored" value={monitoredCount} tone={monitoredCount > 0 ? "ok" : "default"} />
        <KpiTile label="Active Conditions" value={conditionCount} tone={conditionCount > 0 ? "warning" : "default"} />
        <KpiTile label="Monitoring Policies" value={policies.length} />
      </div>

      {actionError && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {showCreateForm && (
        <Panel title="Create monitoring policy" className="mt-6">
          <div className="flex gap-2">
            <label htmlFor="target-asset-id" className="sr-only">
              Authorized NETWORK/IP_ADDRESS asset id
            </label>
            <input
              id="target-asset-id"
              value={newTargetAssetId}
              onChange={(e) => setNewTargetAssetId(e.target.value)}
              placeholder="Authorized NETWORK/IP_ADDRESS asset id"
              className="w-96 rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-200"
            />
            <button
              onClick={handleCreatePolicy}
              disabled={creating || !newTargetAssetId.trim()}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {creating ? "Creating…" : "Create Policy"}
            </button>
          </div>
        </Panel>
      )}

      <Panel title="Network Inventory" className="mt-6">
        <AsyncContent
          state={inventoryState}
          empty={(data) => data.length === 0}
          emptyLabel="No network assets observed yet. Create a NETWORK or IP_ADDRESS asset, obtain an M10 authorization scoped to it, then create a monitoring policy below."
        >
          {(data) => (
            <DataConsole
              columns={inventoryColumns}
              rows={data}
              rowKey={(entry) => entry.asset_id}
              emptyLabel="No network assets observed yet."
            />
          )}
        </AsyncContent>
      </Panel>

      <Panel title="Continuous Monitoring Policies" className="mt-6">
        <AsyncContent
          state={policiesState}
          empty={(data) => data.length === 0}
          emptyLabel="No monitoring policies yet."
        >
          {(data) => (
            <DataConsole
              columns={policyColumns}
              rows={data}
              rowKey={(p) => p.id}
              emptyLabel="No monitoring policies yet."
            />
          )}
        </AsyncContent>
      </Panel>

      <p className="mt-8 text-xs text-gray-600">
        Active network validation telemetry for a run appears in{" "}
        <Link href="/security-operations" className="text-blue-400 hover:underline">
          Security Operations
        </Link>
        .
      </p>
    </div>
  );
}
