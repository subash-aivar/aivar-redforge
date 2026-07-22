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
  approvePlaybook,
  getAutomationPolicy,
  listPlaybooks,
  resetKillSwitch,
  triggerKillSwitch,
  type Playbook,
} from "@/lib/playbooks";

export default function PlaybooksPage() {
  const playbooks = useAsync(() => listPlaybooks(), []);
  const policy = useAsync(() => getAutomationPolicy(), []);
  const [selected, setSelected] = useState<Playbook | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleApprove(p: Playbook) {
    const approver = window.prompt("Approver name/id:");
    if (!approver) return;
    const role = window.prompt("Approver role (e.g. security_manager):", "security_manager");
    if (!role) return;
    setBusy(true);
    setActionError(null);
    try {
      await approvePlaybook(p.playbook_id, p.current_version_number, approver, role);
      setSelected(null);
      playbooks.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Approve failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleKillSwitch() {
    const isActive = policy.data?.kill_switch_state?.toUpperCase() === "ACTIVE" ||
      policy.data?.kill_switch_state?.toUpperCase() === "TRIGGERED";
    if (isActive) {
      if (!window.confirm("Reset the automation kill-switch? This re-enables automated playbook execution.")) return;
      setBusy(true);
      try {
        await resetKillSwitch("analyst");
        policy.reload();
      } catch (e) {
        setActionError(e instanceof Error ? e.message : "Reset failed");
      } finally {
        setBusy(false);
      }
      return;
    }
    const reason = window.prompt("Kill-switch reason (this halts ALL automated playbook execution):");
    if (!reason) return;
    if (!window.confirm("This will halt ALL automated playbook execution platform-wide. Continue?")) return;
    setBusy(true);
    try {
      await triggerKillSwitch("analyst", reason);
      policy.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Kill-switch failed");
    } finally {
      setBusy(false);
    }
  }

  const columns: ConsoleColumn<Playbook>[] = [
    { key: "name", header: "Playbook", width: "24%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "version", header: "Version", width: "10%", render: (r) => `v${r.current_version_number}` },
    { key: "impact", header: "Max Impact", width: "14%", render: (r) => r.max_impact_level },
    { key: "created_by", header: "Created By", width: "18%", render: (r) => r.created_by },
    { key: "approvals", header: "Approvals", width: "20%", render: (r) => r.approved_by.length },
  ];

  const killSwitchActive =
    policy.data?.kill_switch_state?.toUpperCase() === "ACTIVE" ||
    policy.data?.kill_switch_state?.toUpperCase() === "TRIGGERED";

  return (
    <>
      <PageHeader
        title="Playbooks"
        subtitle="Automation policies, playbook approvals, and the automation kill-switch"
        actions={
          <button
            type="button"
            onClick={() => {
              playbooks.reload();
              policy.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <AsyncContent state={playbooks} emptyLabel="No playbooks defined yet.">
            {(rows) => (
              <div className="grid gap-4 sm:grid-cols-2">
                <KpiTile label="Total Playbooks" value={rows.length} />
                <KpiTile
                  label="Active"
                  value={rows.filter((r) => r.status.toUpperCase() === "ACTIVE").length}
                  tone="ok"
                />
              </div>
            )}
          </AsyncContent>
        </div>
        <Panel title="Automation Kill-Switch">
          <AsyncContent state={policy} emptyLabel="No policy configured.">
            {(data) => (
              <div className="space-y-3">
                <StatusPill status={data.kill_switch_state} />
                {data.kill_switch_triggered_by && (
                  <p className="text-xs text-gray-500">
                    Triggered by {data.kill_switch_triggered_by}
                  </p>
                )}
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleKillSwitch}
                  className={`w-full rounded-md border px-3 py-1.5 text-xs font-semibold disabled:opacity-50 ${
                    killSwitchActive
                      ? "border-emerald-800 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-950/70"
                      : "border-red-800 bg-red-950/40 text-red-300 hover:bg-red-950/70"
                  }`}
                >
                  {killSwitchActive ? "Reset Kill-Switch" : "Trigger Kill-Switch"}
                </button>
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <Panel title="Playbooks">
        <AsyncContent state={playbooks} emptyLabel="No playbooks defined yet.">
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows}
              rowKey={(r) => r.playbook_id}
              onRowClick={(r) => setSelected(r)}
              selectedKey={selected?.playbook_id ?? null}
              emptyLabel="No playbooks defined yet."
            />
          )}
        </AsyncContent>
      </Panel>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setActionError(null);
        }}
        title={selected?.name ?? ""}
        subtitle={selected ? `${selected.status} · v${selected.current_version_number}` : undefined}
        fields={
          selected
            ? [
                { label: "Description", value: selected.description },
                { label: "Max Impact Level", value: selected.max_impact_level },
                { label: "Created By", value: selected.created_by },
                { label: "Approved By", value: selected.approved_by.join(", ") || "None yet" },
                ...(actionError
                  ? [{ label: "Action Error", value: <span className="text-red-400">{actionError}</span> }]
                  : []),
                {
                  label: "Actions",
                  value: (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => selected && handleApprove(selected)}
                      className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                    >
                      Approve Version
                    </button>
                  ),
                },
              ]
            : []
        }
      />
    </>
  );
}
