"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  listExecutions,
  cancelExecution,
  type AutomationExecution,
} from "@/lib/automatedAction";

export default function AutomatedActionsPage() {
  const executions = useAsync(() => listExecutions(), []);
  const [selected, setSelected] = useState<AutomationExecution | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleCancel(exec: AutomationExecution) {
    if (!confirm("Cancel this automated action execution?")) return;
    setBusy(true);
    try {
      await cancelExecution(exec.execution_id);
      setSelected(null);
      executions.reload();
    } finally {
      setBusy(false);
    }
  }

  const columns: ConsoleColumn<AutomationExecution>[] = [
    { key: "playbook", header: "Playbook", width: "22%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-300">{r.playbook_id.slice(0, 10)}…</span>
    )},
    { key: "status", header: "Status", width: "16%", render: (r) => <StatusPill status={r.status} /> },
    { key: "progress", header: "Progress", width: "16%", render: (r) => `${r.current_step} / ${r.total_steps}` },
    { key: "operator", header: "Operator", width: "20%", render: (r) => r.operator_id },
    { key: "failure", header: "Failure Reason", width: "26%", render: (r) => r.failure_reason ?? "—" },
  ];

  return (
    <>
      <PageHeader
        title="Automated Actions"
        subtitle="Security playbook executions, escalations, and rollback management"
        actions={
          <button type="button" onClick={() => executions.reload()} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300">
            Refresh
          </button>
        }
      />

      <AsyncContent state={executions}>
        {(execs) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Executions" value={execs.length} />
              <KpiTile label="Running" value={execs.filter(e => e.status === "running" || e.status === "pending").length} tone="warning" />
              <KpiTile label="Completed" value={execs.filter(e => e.status === "completed" || e.status === "succeeded").length} tone="ok" />
              <KpiTile label="Failed" value={execs.filter(e => e.status === "failed" || e.status === "cancelled").length} tone="danger" />
            </div>
            <DataConsole
              columns={columns}
              rows={execs}
              rowKey={(r) => r.execution_id}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No automated actions executed. Configure playbooks to enable automated response."
            />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          title={`Execution ${selected.execution_id.slice(0, 10)}…`}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Status", value: <StatusPill status={selected.status} /> },
            { label: "Progress", value: `${selected.current_step} / ${selected.total_steps} steps` },
            { label: "Operator", value: selected.operator_id },
            { label: "Failure Reason", value: selected.failure_reason ?? "—" },
            ...((selected.status === "running" || selected.status === "pending")
              ? [{
                  label: "Actions",
                  value: (
                    <button
                      onClick={() => handleCancel(selected)}
                      disabled={busy}
                      className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
                    >
                      Cancel Execution
                    </button>
                  ),
                }]
              : []),
          ]}
        />
      )}
    </>
  );
}
