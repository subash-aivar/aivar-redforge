"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { Target, Finding } from "@/lib/types";
import { listExecutions, type ValidationExecution } from "@/lib/validationOperations";
import { listAssets, type Asset } from "@/lib/assets";
import {
  AsyncContent,
  DataConsole,
  FormField,
  InvestigationDrawer,
  KpiTile,
  Panel,
  PageHeader,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";

export default function TargetsPage() {
  const targets = useAsync(() => api.get<Target[]>("/api/v1/targets"), []);
  // Real cross-module context for the drawer — validation executions,
  // findings, and the canonical asset each target resolves to
  // (`Asset.associated_target_id`, the real REDFORGE_TARGET_ID identity
  // scheme bridge) are all fetched once and matched client-side by
  // `target_id`, rather than fabricating a per-target endpoint that
  // doesn't exist.
  const executions = useAsync(() => listExecutions({ limit: 200 }), []);
  const findings = useAsync(() => api.get<Finding[]>("/api/v1/findings"), []);
  const assets = useAsync(() => listAssets(), []);

  const [selected, setSelected] = useState<Target | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  function relatedForTarget(targetId: string) {
    const execs = (executions.data ?? []).filter((e) => e.target_id === targetId);
    const finds = (findings.data ?? []).filter((f) => f.target_id === targetId);
    const asset = (assets.data ?? []).find((a) => a.associated_target_id === targetId) ?? null;
    return { execs, finds, asset };
  }

  const columns: ConsoleColumn<Target>[] = [
    {
      key: "name",
      header: "Target",
      width: "26%",
      render: (t) => <span className="font-medium text-gray-200">{t.name}</span>,
    },
    { key: "type", header: "Type", width: "16%", render: (t) => t.target_type },
    { key: "provider", header: "Provider", width: "14%", render: (t) => t.provider },
    { key: "status", header: "Status", width: "12%", render: (t) => <StatusPill status={t.status} /> },
    {
      key: "validations",
      header: "Validations",
      width: "16%",
      render: (t) => `${relatedForTarget(t.id).execs.length}`,
    },
    {
      key: "findings",
      header: "Findings",
      width: "16%",
      render: (t) => {
        const count = relatedForTarget(t.id).finds.length;
        return <span className={count > 0 ? "text-amber-400" : "text-gray-500"}>{count}</span>;
      },
    },
  ];

  return (
    <>
      <PageHeader
        title="AI Targets"
        subtitle="AI systems under security validation"
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="shrink-0 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
          >
            Register Target
          </button>
        }
      />

      {showCreate && (
        <CreateTargetForm
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            targets.reload();
          }}
        />
      )}

      <AsyncContent state={targets} emptyLabel="No AI targets registered yet.">
        {(list) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Targets" value={list.length} />
              <KpiTile
                label="Active"
                value={list.filter((t) => t.status === "active").length}
                tone="ok"
              />
              <KpiTile
                label="With Validation Runs"
                value={list.filter((t) => relatedForTarget(t.id).execs.length > 0).length}
              />
              <KpiTile
                label="With Open Findings"
                value={list.filter((t) => relatedForTarget(t.id).finds.length > 0).length}
                tone={list.some((t) => relatedForTarget(t.id).finds.length > 0) ? "warning" : "ok"}
              />
            </div>

            <Panel title="Registered targets">
              <DataConsole
                columns={columns}
                rows={list}
                rowKey={(t) => t.id}
                onRowClick={(t) => setSelected(t)}
                selectedKey={selected?.id ?? null}
                emptyLabel="No AI targets registered yet. Register an AI system to begin security validation."
              />
            </Panel>
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          onClose={() => setSelected(null)}
          title={selected.name}
          subtitle={selected.description || "No description"}
          entityId={selected.id}
          fields={(() => {
            const { execs, finds, asset } = relatedForTarget(selected.id);
            return [
              { label: "Status", value: <StatusPill status={selected.status} /> },
              { label: "Type", value: selected.target_type },
              { label: "Provider", value: selected.provider },
              { label: "Endpoint", value: selected.endpoint },
              {
                label: "Canonical Asset",
                value: asset ? (
                  <Link href="/assets" className="text-red-400 hover:text-red-300">
                    {asset.name} →
                  </Link>
                ) : (
                  "Not yet resolved to a canonical asset"
                ),
              },
              {
                label: `Validation Executions (${execs.length})`,
                value:
                  execs.length === 0 ? (
                    "No validation runs yet."
                  ) : (
                    <div className="space-y-1">
                      {execs.slice(0, 8).map((e) => (
                        <div
                          key={e.id}
                          className="flex items-center justify-between rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs"
                        >
                          <StatusPill status={e.status} />
                          <span className="text-gray-500">{fmtTime(e.started_at)}</span>
                        </div>
                      ))}
                      <Link
                        href="/validation-operations"
                        className="mt-1 inline-block text-xs text-red-400 hover:text-red-300"
                      >
                        View in Validation Operations →
                      </Link>
                    </div>
                  ),
              },
              {
                label: `Findings (${finds.length})`,
                value:
                  finds.length === 0 ? (
                    "No findings for this target."
                  ) : (
                    <div className="space-y-1">
                      {finds.slice(0, 8).map((f) => (
                        <div
                          key={f.id}
                          className="flex items-center justify-between rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs"
                        >
                          <span className="text-gray-300">{f.severity}</span>
                          <span className="text-gray-500">{f.status}</span>
                        </div>
                      ))}
                      <Link
                        href="/findings"
                        className="mt-1 inline-block text-xs text-red-400 hover:text-red-300"
                      >
                        View in Findings →
                      </Link>
                    </div>
                  ),
              },
            ];
          })()}
        />
      )}
    </>
  );
}

function CreateTargetForm({ onClose, onCreated }: { onClose: () => void; onCreated: (t: Target) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetType, setTargetType] = useState("llm_application");
  const [provider, setProvider] = useState("openai");
  const [endpoint, setEndpoint] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const t = await api.post<Target>("/api/v1/targets", {
        name, description, target_type: targetType, provider, endpoint,
      });
      onCreated(t);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create target");
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none";

  return (
    <Panel title="Register AI Target" className="mb-6">
      <form onSubmit={submit} className="space-y-3 p-4">
        <FormField label="Target name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Support Chatbot"
            className={inputClass}
          />
        </FormField>
        <FormField label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
            className={inputClass}
          />
        </FormField>
        <div className="grid grid-cols-2 gap-3">
          <FormField label="Target type">
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white"
            >
              <option value="llm_application">LLM Application</option>
              <option value="ai_agent">AI Agent</option>
              <option value="rag_system">RAG System</option>
              <option value="mcp_server">MCP Server</option>
              <option value="ai_api">AI API</option>
              <option value="ai_workflow">AI Workflow</option>
              <option value="autonomous_agent">Autonomous Agent</option>
            </select>
          </FormField>
          <FormField label="Provider">
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white"
            >
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="google">Google</option>
              <option value="local">Local</option>
            </select>
          </FormField>
        </div>
        <FormField label="Endpoint URL" required>
          <input
            type="url"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://api.example.com/v1/chat"
            className={inputClass}
          />
        </FormField>
        {error && (
          <div role="alert" className="text-sm text-red-400">
            {error}
          </div>
        )}
        <div className="flex gap-3">
          <button type="submit" disabled={loading} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50">
            {loading ? "Creating..." : "Register Target"}
          </button>
          <button type="button" onClick={onClose} className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-400 hover:text-white">Cancel</button>
        </div>
      </form>
    </Panel>
  );
}
