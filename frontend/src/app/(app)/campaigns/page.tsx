"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  CampaignDetailView,
  type CampaignSummary,
  type CampaignDetail,
} from "./campaign-graph";

interface ProviderOption {
  id: string;
  name: string;
  provider_type: string;
  enabled: boolean;
  credential_configured: boolean;
  auth_ref: string;
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [selected, setSelected] = useState<CampaignDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);

  useEffect(() => {
    api
      .get<CampaignSummary[]>("/api/v1/red-team/campaigns")
      .then(setCampaigns)
      .catch((err) => setApiError(err.message || "Failed to load campaigns"))
      .finally(() => setLoading(false));
  }, []);

  async function openDetail(id: string) {
    setDetailLoading(true);
    try {
      const detail = await api.get<CampaignDetail>(
        `/api/v1/red-team/campaigns/${id}`
      );
      setSelected(detail);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load campaign";
      setApiError(msg);
    } finally {
      setDetailLoading(false);
    }
  }

  function handleLaunched(c: CampaignSummary) {
    setCampaigns((prev) => [c, ...prev]);
    setShowCreate(false);
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Red Team Campaigns</h1>
          <p className="mt-1 text-sm text-gray-400">
            Autonomous AI security red-team operations
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
        >
          Launch Campaign
        </button>
      </div>

      {showCreate && (
        <LaunchCampaignForm
          onClose={() => setShowCreate(false)}
          onLaunched={handleLaunched}
        />
      )}

      {apiError && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {apiError}
        </div>
      )}

      {selected && (
        <CampaignDetailView
          detail={selected}
          onClose={() => setSelected(null)}
        />
      )}

      {loading ? (
        <div className="mt-8 text-center text-gray-400">Loading campaigns...</div>
      ) : campaigns.length === 0 ? (
        <div className="mt-8 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
          <p className="text-gray-400">No campaigns executed yet.</p>
          <p className="mt-2 text-sm text-gray-500">
            Launch a red-team campaign to validate your AI system&apos;s security posture.
          </p>
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {campaigns.map((c) => (
            <button
              key={c.campaign_id}
              onClick={() => openDetail(c.campaign_id)}
              disabled={detailLoading}
              className="w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left hover:border-gray-600 transition disabled:opacity-50"
            >
              <div className="flex items-center justify-between">
                <div className="font-medium text-white">{c.objective_name}</div>
                <StateChip state={c.state} goalAchieved={c.goal_achieved} />
              </div>
              <div className="mt-2 flex gap-4 text-xs text-gray-500">
                <span>Nodes: {c.total_nodes}</span>
                <span>Executed: {c.nodes_executed}</span>
                <span>Completed: {c.completed_nodes}</span>
                <span>Failed: {c.failed_nodes}</span>
                <span>Confidence: {(c.intelligence_confidence * 100).toFixed(0)}%</span>
                <span>{c.duration_ms}ms</span>
              </div>
              {c.failure_reason && (
                <div className="mt-1 text-xs text-red-400">{c.failure_reason}</div>
              )}
              <div className="mt-1 text-xs text-gray-600">
                {new Date(c.created_at).toLocaleString()}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function StateChip({
  state,
  goalAchieved,
}: {
  state: string;
  goalAchieved: boolean;
}) {
  const colors: Record<string, string> = {
    completed: goalAchieved
      ? "bg-yellow-950 text-yellow-400"
      : "bg-green-950 text-green-400",
    failed: "bg-red-950 text-red-400",
    cancelled: "bg-gray-800 text-gray-400",
    running: "bg-blue-950 text-blue-400",
  };
  const cls = colors[state] ?? "bg-gray-800 text-gray-400";
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {state}
      {goalAchieved ? " ✓" : ""}
    </span>
  );
}

// ─── Launch Form ──────────────────────────────────────────────────────────────

function LaunchCampaignForm({
  onClose,
  onLaunched,
}: {
  onClose: () => void;
  onLaunched: (c: CampaignSummary) => void;
}) {
  const [targetId, setTargetId] = useState("");
  const [targetName, setTargetName] = useState("");
  const [targetEndpoint, setTargetEndpoint] = useState("");
  const [providerId, setProviderId] = useState("");
  const [goal, setGoal] = useState("jailbreak");
  const [model, setModel] = useState("gpt-4o-mini");
  const [error, setError] = useState("");
  const [launching, setLaunching] = useState(false);

  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [providersLoading, setProvidersLoading] = useState(true);
  const [providersError, setProvidersError] = useState("");

  useEffect(() => {
    api
      .get<ProviderOption[]>("/api/v1/providers")
      .then((list) => {
        setProviders(list);
        const first = list.find((p) => p.enabled && p.credential_configured);
        if (first) setProviderId(first.id);
      })
      .catch((err) => {
        setProvidersError(err.message || "Failed to load providers");
      })
      .finally(() => setProvidersLoading(false));
  }, []);

  const selectedProvider = providers.find((p) => p.id === providerId) ?? null;

  function providerStatusMessage(): string | null {
    if (providersLoading) return null;
    if (providers.length === 0) return "No providers configured. Register a provider first.";
    if (!providerId) return "Select a provider to continue.";
    if (!selectedProvider) return null;
    if (!selectedProvider.enabled) return `Provider '${selectedProvider.name}' is disabled.`;
    if (!selectedProvider.credential_configured)
      return `Provider '${selectedProvider.name}' has no credential reference configured (auth_ref missing). Update the provider to add one.`;
    return null;
  }

  const statusMsg = providerStatusMessage();
  const canSubmit =
    !launching &&
    !!providerId &&
    selectedProvider?.enabled === true &&
    selectedProvider?.credential_configured === true;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setLaunching(true);
    setError("");
    try {
      const result = await api.post<CampaignSummary>(
        "/api/v1/red-team/campaigns",
        {
          target_id: targetId || `target-${Date.now()}`,
          target_name: targetName,
          target_endpoint: targetEndpoint,
          provider_id: providerId,
          model,
          goal,
          max_attacks_per_category: 2,
          severity_minimum: "medium",
        }
      );
      onLaunched(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Campaign launch failed";
      setError(msg);
    } finally {
      setLaunching(false);
    }
  }

  return (
    <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
      <h2 className="text-lg font-semibold text-white">Launch Red Team Campaign</h2>
      <p className="mt-1 text-xs text-gray-500">
        Provider credentials are resolved server-side from a registered provider configuration.
        No credential material is submitted from the browser.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <input
          value={targetName}
          onChange={(e) => setTargetName(e.target.value)}
          placeholder="Target name"
          required
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
        />
        <input
          value={targetEndpoint}
          onChange={(e) => setTargetEndpoint(e.target.value)}
          placeholder="Target endpoint (e.g. https://api.openai.com/v1)"
          required
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
        />
        <input
          value={targetId}
          onChange={(e) => setTargetId(e.target.value)}
          placeholder="Target ID (optional — auto-generated if blank)"
          className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
        />

        {/* Provider selector — no raw credential fields */}
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-400">
            Provider configuration
          </label>
          {providersLoading ? (
            <div className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-500">
              Loading providers...
            </div>
          ) : providersError ? (
            <div className="rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
              {providersError}
            </div>
          ) : providers.length === 0 ? (
            <div className="rounded-lg border border-yellow-800 bg-yellow-950 px-3 py-2 text-xs text-yellow-300">
              No provider configured. Register a provider first.
            </div>
          ) : (
            <select
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
              required
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white"
            >
              <option value="">Select a provider…</option>
              {providers.map((p) => {
                const credStatus = !p.credential_configured
                  ? " — no credential"
                  : "";
                const enabledStatus = !p.enabled ? " [disabled]" : "";
                return (
                  <option key={p.id} value={p.id} disabled={!p.enabled || !p.credential_configured}>
                    {p.name} ({p.provider_type}){credStatus}{enabledStatus}
                  </option>
                );
              })}
            </select>
          )}
          {statusMsg && (
            <div className="mt-1 rounded-lg border border-yellow-800 bg-yellow-950 px-3 py-2 text-xs text-yellow-300">
              {statusMsg}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <select
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white"
          >
            <option value="jailbreak">Jailbreak</option>
            <option value="prompt_injection">Prompt Injection</option>
            <option value="data_extraction">Data Extraction</option>
            <option value="goal_hijacking">Goal Hijacking</option>
            <option value="sensitive_disclosure">Sensitive Disclosure</option>
            <option value="policy_violation">Policy Violation</option>
          </select>
          <input
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="Model (e.g. gpt-4o-mini)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500"
          />
        </div>

        {error && <div className="text-sm text-red-400">{error}</div>}
        <div className="flex gap-3">
          <button
            type="submit"
            disabled={!canSubmit}
            className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {launching ? "Launching…" : "Launch Campaign"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-400 hover:text-white"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
