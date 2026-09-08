"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import {
  AsyncContent,
  DataConsole,
  FormField,
  InvestigationDrawer,
  KpiTile,
  Panel,
  PageHeader,
  fmtTime,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  toCanonicalNodeState,
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

const STATE_TONE: Record<string, string> = {
  completed: "text-green-400",
  failed: "text-red-400",
  cancelled: "text-gray-400",
  running: "text-blue-400",
};

export default function CampaignsPage() {
  const campaignsState = useAsync<CampaignSummary[]>(
    () => api.get<CampaignSummary[]>("/api/v1/red-team/campaigns"),
    []
  );
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<CampaignDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  async function openDetail(id: string) {
    setSelectedId(id);
    setDetailLoading(true);
    setDetailError("");
    try {
      const detail = await api.get<CampaignDetail>(
        `/api/v1/red-team/campaigns/${id}`
      );
      setSelected(detail);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load campaign";
      setDetailError(msg);
    } finally {
      setDetailLoading(false);
    }
  }

  function closeDetail() {
    setSelected(null);
    setSelectedId(null);
  }

  function handleLaunched() {
    setShowCreate(false);
    campaignsState.reload();
  }

  const campaigns = campaignsState.data ?? [];
  const total = campaigns.length;
  const runningCount = campaigns.filter((c) => c.state === "running").length;
  const completedCount = campaigns.filter((c) => c.state === "completed").length;
  const totalFindings = campaigns.reduce(
    (sum, c) => sum + (c.completed_nodes ?? 0),
    0
  );

  const columns: ConsoleColumn<CampaignSummary>[] = [
    {
      key: "name",
      header: "Objective",
      render: (c) => (
        <div>
          <span className="font-medium text-gray-100">{c.objective_name}</span>
          {c.goal_achieved && (
            <span className="ml-2 text-[10px] text-yellow-400">goal achieved</span>
          )}
        </div>
      ),
    },
    {
      key: "state",
      header: "State",
      render: (c) => (
        <span className={`font-mono text-xs font-semibold ${STATE_TONE[c.state] ?? "text-gray-400"}`}>
          {c.state.toUpperCase()}
        </span>
      ),
    },
    {
      key: "nodes",
      header: "Nodes",
      render: (c) => (
        <span className="text-xs">
          {c.completed_nodes}/{c.total_nodes} completed
          {c.failed_nodes > 0 && (
            <span className="ml-1 text-red-400">({c.failed_nodes} failed)</span>
          )}
        </span>
      ),
    },
    {
      key: "confidence",
      header: "Confidence",
      render: (c) => <span className="text-xs">{(c.intelligence_confidence * 100).toFixed(0)}%</span>,
    },
    {
      key: "duration",
      header: "Duration",
      render: (c) => <span className="text-xs">{c.duration_ms}ms</span>,
    },
    {
      key: "created",
      header: "Created",
      render: (c) => <span className="text-xs text-gray-500">{fmtTime(c.created_at)}</span>,
    },
  ];

  const drawerFields: DrawerField[] = selected
    ? [
        { label: "State", value: selected.state.toUpperCase() },
        { label: "Goal achieved", value: selected.goal_achieved ? "Yes" : "No" },
        { label: "Target ID", value: selected.target_id },
        { label: "Organization", value: selected.organization_id },
        {
          label: "Nodes",
          value: `${selected.total_nodes} total · ${selected.nodes_executed} executed · ${selected.completed_nodes} completed · ${selected.failed_nodes} failed · ${selected.blocked_nodes} blocked`,
        },
        {
          label: "Intelligence confidence",
          value: `${(selected.intelligence_confidence * 100).toFixed(0)}%`,
        },
        { label: "Duration", value: `${selected.duration_ms}ms` },
        ...(selected.failure_reason
          ? [{ label: "Failure reason", value: selected.failure_reason }]
          : []),
        { label: "Created", value: fmtTime(selected.created_at) },
        {
          label: "Attack nodes",
          value:
            selected.graph_nodes.length === 0 ? (
              "No attack nodes recorded."
            ) : (
              <div className="space-y-1.5">
                {selected.graph_nodes.map((node) => (
                  <div key={node.id} className="rounded border border-gray-800 bg-gray-900/60 px-2 py-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs">{node.id}</span>
                      <span className="text-[10px] font-semibold text-gray-400">
                        {toCanonicalNodeState(node.state)}
                      </span>
                    </div>
                    {node.attack_category && (
                      <div className="text-[11px] text-gray-500">{node.attack_category}</div>
                    )}
                    {(node.findings_count ?? 0) > 0 && (
                      <div className="text-[11px] text-gray-500">{node.findings_count} findings</div>
                    )}
                    {node.failure_reason && (
                      <div className="text-[11px] text-red-400">{node.failure_reason}</div>
                    )}
                  </div>
                ))}
              </div>
            ),
        },
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="Red Team Campaigns"
        subtitle="Autonomous AI security red-team operations"
        actions={
          <button
            onClick={() => setShowCreate((v) => !v)}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:text-white"
          >
            {showCreate ? "Hide launch form" : "Launch Campaign"}
          </button>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile label="Total campaigns" value={total} />
        <KpiTile label="Running" value={runningCount} tone={runningCount > 0 ? "ok" : "default"} />
        <KpiTile label="Completed" value={completedCount} />
        <KpiTile label="Completed nodes (all campaigns)" value={totalFindings} />
      </div>

      {showCreate && (
        <Panel title="Launch Red Team Campaign" className="mt-6">
          <LaunchCampaignForm onClose={() => setShowCreate(false)} onLaunched={handleLaunched} />
        </Panel>
      )}

      {detailError && (
        <div role="alert" className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {detailError}
        </div>
      )}

      <Panel title="Campaigns" className="mt-6">
        <AsyncContent
          state={campaignsState}
          empty={(data) => data.length === 0}
          emptyLabel="No campaigns executed yet. Launch a red-team campaign to validate your AI system's security posture."
        >
          {(data) => (
            <DataConsole
              columns={columns}
              rows={data}
              rowKey={(c) => c.campaign_id}
              onRowClick={(c) => openDetail(c.campaign_id)}
              selectedKey={selectedId}
              emptyLabel="No campaigns executed yet."
            />
          )}
        </AsyncContent>
        {detailLoading && (
          <div className="mt-2 text-xs text-gray-500">Loading campaign detail…</div>
        )}
      </Panel>

      <InvestigationDrawer
        open={!!selected}
        onClose={closeDetail}
        title={selected ? `Campaign: ${selected.objective_name}` : ""}
        subtitle={selected ? selected.campaign_id : undefined}
        entityId={selected?.campaign_id}
        fields={drawerFields}
      />
    </div>
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

  const providersState = useAsync<ProviderOption[]>(
    () =>
      api.get<ProviderOption[]>("/api/v1/providers").then((list) => {
        const first = list.find((p) => p.enabled && p.credential_configured);
        if (first) setProviderId(first.id);
        return list;
      }),
    []
  );
  const providers = providersState.data ?? [];

  const selectedProvider = providers.find((p) => p.id === providerId) ?? null;

  function providerStatusMessage(): string | null {
    if (providersState.loading) return null;
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
    <div>
      <p className="text-xs text-gray-500">
        Provider credentials are resolved server-side from a registered provider configuration.
        No credential material is submitted from the browser.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <FormField label="Target name" required>
          <input
            value={targetName}
            onChange={(e) => setTargetName(e.target.value)}
            placeholder="e.g. Support Chatbot"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
          />
        </FormField>
        <FormField label="Target endpoint" required>
          <input
            type="url"
            value={targetEndpoint}
            onChange={(e) => setTargetEndpoint(e.target.value)}
            placeholder="https://api.openai.com/v1"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
          />
        </FormField>
        <FormField label="Target ID" hint="Optional — auto-generated if blank.">
          <input
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            placeholder="Optional"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
          />
        </FormField>

        {/* Provider selector — no raw credential fields */}
        <div>
          {providersState.loading ? (
            <div className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-500" role="status">
              Loading providers...
            </div>
          ) : providersState.error ? (
            <div role="alert" className="rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-xs text-red-300">
              {providersState.error}
            </div>
          ) : providers.length === 0 ? (
            <div role="status" className="rounded-lg border border-yellow-800 bg-yellow-950 px-3 py-2 text-xs text-yellow-300">
              No provider configured. Register a provider first.
            </div>
          ) : (
            <FormField label="Provider configuration" required>
              <select
                value={providerId}
                onChange={(e) => setProviderId(e.target.value)}
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
            </FormField>
          )}
          {statusMsg && (
            <div role="status" className="mt-1 rounded-lg border border-yellow-800 bg-yellow-950 px-3 py-2 text-xs text-yellow-300">
              {statusMsg}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <FormField label="Attack goal">
            <select
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white"
            >
              <option value="jailbreak">Jailbreak</option>
              <option value="prompt_injection">Prompt Injection</option>
              <option value="data_extraction">Data Extraction</option>
              <option value="goal_hijacking">Goal Hijacking</option>
              <option value="sensitive_disclosure">Sensitive Disclosure</option>
              <option value="policy_violation">Policy Violation</option>
            </select>
          </FormField>
          <FormField label="Model">
            <input
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="e.g. gpt-4o-mini"
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500"
            />
          </FormField>
        </div>

        {error && <div role="alert" className="text-sm text-red-400">{error}</div>}
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
