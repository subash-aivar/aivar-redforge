"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  listPolicies,
  listViolations,
  listAgents,
  type AgentPolicy,
  type GovernanceViolation,
  type AgentRegistration,
} from "@/lib/aiGovernance";

export default function AIGovernancePage() {
  const policies = useAsync(() => listPolicies(), []);
  const violations = useAsync(() => listViolations(), []);
  const agents = useAsync(() => listAgents(), []);
  const [tab, setTab] = useState<"policies" | "violations" | "agents">("policies");

  return (
    <>
      <PageHeader
        title="AI Agent Governance"
        subtitle="Agent policies, compliance monitoring, and violation management"
      />

      {/* KPI row */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <AsyncContent state={policies}>
          {(p) => <KpiTile label="Policies" value={p.length} />}
        </AsyncContent>
        <AsyncContent state={violations}>
          {(v) => <KpiTile label="Violations" value={v.length} tone={v.length > 0 ? "critical" : "low"} />}
        </AsyncContent>
        <AsyncContent state={agents}>
          {(a) => <KpiTile label="Agents" value={a.length} />}
        </AsyncContent>
        <AsyncContent state={agents}>
          {(a) => <KpiTile label="Active" value={a.filter(ag => ag.status === "active").length} tone="low" />}
        </AsyncContent>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["policies", "violations", "agents"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "policies" && <PoliciesTab state={policies} />}
      {tab === "violations" && <ViolationsTab state={violations} />}
      {tab === "agents" && <AgentsTab state={agents} />}
    </>
  );
}

function PoliciesTab({ state }: { state: ReturnType<typeof useAsync<AgentPolicy[]>> }) {
  const cols: ConsoleColumn<AgentPolicy>[] = [
    { key: "name", header: "Policy", width: "28%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "rules", header: "Rules", width: "10%", render: (r) => `${r.rules.length}` },
    { key: "desc", header: "Description", width: "36%", render: (r) => <span className="text-gray-400 text-xs truncate">{r.description}</span> },
    { key: "id", header: "ID", width: "14%", render: (r) => <span className="font-mono text-[10px] text-gray-600">{r.policy_id.slice(0,10)}…</span> },
  ];
  return (
    <AsyncContent state={state}>
      {(list) => <DataConsole columns={cols} rows={list} rowKey={(r) => r.policy_id} emptyMessage="No governance policies configured." />}
    </AsyncContent>
  );
}

function ViolationsTab({ state }: { state: ReturnType<typeof useAsync<GovernanceViolation[]>> }) {
  const cols: ConsoleColumn<GovernanceViolation>[] = [
    { key: "desc", header: "Description", width: "34%", render: (r) => <span className="text-gray-200 text-sm">{r.description}</span> },
    { key: "severity", header: "Severity", width: "12%", render: (r) => <StatusPill status={r.severity} /> },
    { key: "agent", header: "Agent", width: "14%", render: (r) => <span className="font-mono text-[11px] text-gray-400">{r.agent_id.slice(0,10)}…</span> },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "detected", header: "Detected", width: "14%", render: (r) => r.detected_at?.slice(0,10) || "—" },
    { key: "id", header: "ID", width: "14%", render: (r) => <span className="font-mono text-[10px] text-gray-600">{r.violation_id.slice(0,8)}…</span> },
  ];
  return (
    <AsyncContent state={state}>
      {(list) => <DataConsole columns={cols} rows={list} rowKey={(r) => r.violation_id} emptyMessage="No governance violations detected." />}
    </AsyncContent>
  );
}

function AgentsTab({ state }: { state: ReturnType<typeof useAsync<AgentRegistration[]>> }) {
  const cols: ConsoleColumn<AgentRegistration>[] = [
    { key: "name", header: "Agent", width: "22%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "type", header: "Type", width: "14%", render: (r) => r.agent_type },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "caps", header: "Capabilities", width: "24%", render: (r) => r.capabilities.slice(0,3).join(", ") || "—" },
    { key: "policies", header: "Policies", width: "10%", render: (r) => `${r.policies.length}` },
    { key: "registered", header: "Registered", width: "18%", render: (r) => r.registered_at?.slice(0,10) || "—" },
  ];
  return (
    <AsyncContent state={state}>
      {(list) => <DataConsole columns={cols} rows={list} rowKey={(r) => r.agent_id} emptyMessage="No AI agents registered." />}
    </AsyncContent>
  );
}
