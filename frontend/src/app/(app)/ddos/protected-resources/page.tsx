"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  listProtectedResources,
  createProtectedResource,
  deleteProtectedResource,
  getDetectionPolicy,
  type ProtectedResource,
  type DetectionPolicy,
} from "@/lib/ddos";

function CriticalityBadge({ criticality }: { criticality: string }) {
  const cls =
    criticality === "CRITICAL" ? "border-red-800 bg-red-950 text-red-400" :
    criticality === "HIGH" ? "border-orange-800 bg-orange-950 text-orange-400" :
    criticality === "MEDIUM" ? "border-yellow-800 bg-yellow-950 text-yellow-400" :
    "border-gray-700 bg-gray-800 text-gray-400";
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${cls}`}>
      {criticality}
    </span>
  );
}

function ResourcePolicyDetails({ resourceId }: { resourceId: string }) {
  const [policy, setPolicy] = useState<DetectionPolicy | null>(null);

  useEffect(() => {
    getDetectionPolicy(resourceId).then(setPolicy).catch(() => {});
  }, [resourceId]);

  if (!policy) return <span className="text-xs text-gray-500">No policy</span>;

  return (
    <div className="text-xs text-gray-400">
      <span className={`mr-2 ${policy.enabled ? "text-emerald-400" : "text-gray-600"}`}>
        {policy.enabled ? "● Active" : "○ Disabled"}
      </span>
      {policy.profile} · {policy.window_seconds}s windows · {policy.mitigation_mode}
    </div>
  );
}

export default function ProtectedResourcesPage() {
  const [resources, setResources] = useState<ProtectedResource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    name: "",
    description: "",
    scope_type: "any",
    scope_value: "",
    criticality: "MEDIUM",
  });

  const load = async () => {
    try {
      const r = await listProtectedResources();
      setResources(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load resources");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    if (!form.name.trim()) return;
    setCreating(true);
    try {
      await createProtectedResource({
        name: form.name,
        description: form.description,
        scope_type: form.scope_type,
        scope_value: form.scope_value || undefined,
        criticality: form.criticality,
      });
      setForm({ name: "", description: "", scope_type: "any", scope_value: "", criticality: "MEDIUM" });
      setShowCreate(false);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create resource");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Remove protected resource "${name}"? This will also remove its detection policy.`)) return;
    try {
      await deleteProtectedResource(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete resource");
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Protected Resources</h1>
          <p className="mt-1 text-sm text-gray-400">
            Resources under active DDoS detection monitoring
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/ddos" className="text-sm text-blue-400 hover:underline">← Overview</Link>
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg border border-emerald-800 bg-emerald-950 px-4 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-900"
          >
            + Add Resource
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-800 bg-red-950 p-4 text-red-300">{error}</div>
      )}

      {/* Create form */}
      {showCreate && (
        <div className="rounded-xl border border-gray-700 bg-gray-900 p-5">
          <h3 className="mb-4 text-base font-semibold text-white">Add Protected Resource</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-gray-400">Name *</label>
              <input
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="Production API Gateway"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-600"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">Criticality</label>
              <select
                value={form.criticality}
                onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
              >
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">Scope Type</label>
              <select
                value={form.scope_type}
                onChange={e => setForm(f => ({ ...f, scope_type: e.target.value }))}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
              >
                <option value="any">Any (all org traffic)</option>
                <option value="ip">IP Address</option>
                <option value="subnet">Subnet</option>
                <option value="service">Service Name</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">Scope Value</label>
              <input
                value={form.scope_value}
                onChange={e => setForm(f => ({ ...f, scope_value: e.target.value }))}
                placeholder="e.g. 10.0.1.0/24 or api-gateway"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-600"
              />
            </div>
            <div className="md:col-span-2">
              <label className="mb-1 block text-xs text-gray-400">Description</label>
              <input
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-600"
              />
            </div>
          </div>
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCreate}
              disabled={creating || !form.name.trim()}
              className="rounded-lg border border-emerald-800 bg-emerald-950 px-4 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-900 disabled:opacity-50"
            >
              {creating ? "Creating…" : "Create Resource"}
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-400 hover:bg-gray-700"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-gray-500">
          Loading resources…
        </div>
      ) : resources.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-12 text-center">
          <div className="text-4xl mb-4">▣</div>
          <div className="text-lg font-medium text-gray-300">No protected resources configured</div>
          <div className="mt-1 text-sm text-gray-500">
            Add your first protected resource to start DDoS monitoring
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {resources.map(r => (
            <div key={r.id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-white">{r.name}</span>
                    <CriticalityBadge criticality={r.criticality} />
                    <span className={`rounded-full border px-2 py-0.5 text-xs ${r.monitoring_enabled ? "border-emerald-800 text-emerald-400" : "border-gray-700 text-gray-500"}`}>
                      {r.monitoring_enabled ? "Monitoring On" : "Monitoring Off"}
                    </span>
                  </div>
                  {r.description && (
                    <div className="mt-1 text-sm text-gray-400">{r.description}</div>
                  )}
                  <div className="mt-1 flex items-center gap-4 text-xs text-gray-500">
                    <span>Scope: <span className="font-mono text-gray-400">{r.scope_type}{r.scope_value ? ` (${r.scope_value})` : ""}</span></span>
                    {r.monitored_ports && r.monitored_ports.length > 0 && (
                      <span>Ports: <span className="font-mono text-gray-400">{r.monitored_ports.join(", ")}</span></span>
                    )}
                  </div>
                  <div className="mt-2">
                    <ResourcePolicyDetails resourceId={r.id} />
                  </div>
                </div>
                <div className="flex flex-col gap-2 flex-shrink-0">
                  <Link
                    href={`/ddos/traffic?resource_id=${r.id}`}
                    className="rounded border border-blue-800 bg-blue-950 px-3 py-1 text-xs font-medium text-blue-300 hover:bg-blue-900 text-center"
                  >
                    Traffic
                  </Link>
                  <button
                    onClick={() => handleDelete(r.id, r.name)}
                    className="rounded border border-gray-700 bg-gray-800 px-3 py-1 text-xs text-gray-500 hover:border-red-900 hover:bg-red-950 hover:text-red-400"
                  >
                    Remove
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
