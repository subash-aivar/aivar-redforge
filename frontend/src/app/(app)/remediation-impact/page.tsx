"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  FormField,
  FormModal,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  useAsync,
  fmtTime,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  generatePlan,
  commitPlan,
  listPlans,
  type ExposureReductionPlanDTO,
  type RemediationCandidate,
} from "@/lib/remediationImpact";
import { getMe } from "@/lib/auth";

export default function RemediationImpactPage() {
  const plans = useAsync(() => listPlans(), []);
  const [selected, setSelected] = useState<ExposureReductionPlanDTO | null>(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [busy, setBusy] = useState(false);

  async function handleCommit(plan: ExposureReductionPlanDTO) {
    setBusy(true);
    try {
      const me = await getMe().catch(() => null);
      const updated = await commitPlan(plan.plan_id, me?.email || "console");
      setSelected(updated);
      plans.reload();
    } finally {
      setBusy(false);
    }
  }

  const cols: ConsoleColumn<ExposureReductionPlanDTO>[] = [
    { key: "plan", header: "Plan ID", width: "20%", render: (r) => <span className="font-mono text-xs text-gray-300">{r.plan_id.slice(0, 12)}…</span> },
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "reduction", header: "Projected Reduction", width: "18%", render: (r) => <span className="font-semibold text-emerald-400">{r.projected_exposure_reduction.toFixed(2)}</span> },
    { key: "impact", header: "Business Impact", width: "16%", render: (r) => r.estimated_business_impact.toFixed(2) },
    { key: "steps", header: "Steps", width: "10%", render: (r) => r.plan_steps.length },
    { key: "generated", header: "Generated", width: "14%", render: (r) => fmtTime(r.generated_at) },
    { key: "stale", header: "Stale", width: "8%", render: (r) => (r.is_stale ? <span className="text-amber-400">Yes</span> : <span className="text-gray-500">No</span>) },
  ];

  return (
    <>
      <PageHeader
        title="Remediation Impact"
        subtitle="Budget-constrained exposure reduction planning and commitment"
        actions={
          <button
            onClick={() => setShowGenerate(true)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
          >
            Generate Plan
          </button>
        }
      />

      <AsyncContent state={plans} empty={(d) => d.length === 0} emptyLabel="No exposure reduction plans generated yet.">
        {(list) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Plans" value={list.length} />
              <KpiTile label="Committed" value={list.filter((p) => p.status.toUpperCase() === "COMMITTED").length} tone="ok" />
              <KpiTile label="Draft" value={list.filter((p) => p.status.toUpperCase() === "DRAFT" || p.status.toUpperCase() === "GENERATED").length} tone="warning" />
              <KpiTile label="Stale" value={list.filter((p) => p.is_stale).length} tone="danger" />
            </div>
            <DataConsole columns={cols} rows={list} rowKey={(r) => r.plan_id} onRowClick={setSelected} emptyLabel="No exposure reduction plans generated yet." />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          title={`Plan ${selected.plan_id.slice(0, 12)}…`}
          subtitle={selected.algorithm}
          onClose={() => setSelected(null)}
          fields={planFields(selected, handleCommit, busy)}
        />
      )}

      {showGenerate && (
        <GeneratePlanModal
          onClose={() => setShowGenerate(false)}
          onGenerated={(plan) => {
            plans.reload();
            setShowGenerate(false);
            setSelected(plan);
          }}
        />
      )}
    </>
  );
}

function planFields(
  p: ExposureReductionPlanDTO,
  onCommit: (p: ExposureReductionPlanDTO) => void,
  busy: boolean
): DrawerField[] {
  return [
    { label: "Status", value: <StatusPill status={p.status} /> },
    { label: "Projected Exposure Reduction", value: <span className="font-semibold text-emerald-400">{p.projected_exposure_reduction.toFixed(3)}</span> },
    { label: "Estimated Business Impact", value: p.estimated_business_impact.toFixed(3) },
    { label: "Algorithm", value: `${p.algorithm} (${p.approximation_mode})` },
    { label: "Top K / Sample Size", value: `${p.top_k} / ${p.sample_size}` },
    { label: "Generated At", value: fmtTime(p.generated_at) },
    { label: "Committed", value: p.committed_at ? `${fmtTime(p.committed_at)} by ${p.committed_by}` : "Not committed" },
    {
      label: `Ranked Steps (${p.plan_steps.length})`,
      value: (
        <div className="divide-y divide-gray-800">
          {p.plan_steps
            .slice()
            .sort((a, b) => a.rank - b.rank)
            .map((s) => (
              <div key={s.remediation_id} className="flex items-center justify-between py-1.5">
                <div>
                  <span className="mr-2 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">#{s.rank}</span>
                  <span className="font-mono text-xs text-gray-300">{s.remediation_id}</span>
                </div>
                <span className="text-xs font-semibold text-emerald-400">-{s.marginal_delta.toFixed(3)}</span>
              </div>
            ))}
        </div>
      ),
    },
    ...(p.status.toUpperCase() !== "COMMITTED"
      ? [{
          label: "Actions",
          value: (
            <button
              onClick={() => onCommit(p)}
              disabled={busy}
              className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
            >
              {busy ? "Committing…" : "Commit Plan"}
            </button>
          ),
        }]
      : []),
  ];
}

function GeneratePlanModal({
  onClose,
  onGenerated,
}: {
  onClose: () => void;
  onGenerated: (plan: ExposureReductionPlanDTO) => void;
}) {
  const [candidates, setCandidates] = useState<RemediationCandidate[]>([
    { remediation_id: "", affected_asset_refs: [], estimated_amplifier_removals: [], estimated_base_reduction: 0 },
  ]);
  const [planBudget, setPlanBudget] = useState(10);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function updateCandidate(i: number, patch: Partial<RemediationCandidate>) {
    setCandidates((prev) => prev.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function addCandidate() {
    setCandidates((prev) => [
      ...prev,
      { remediation_id: "", affected_asset_refs: [], estimated_amplifier_removals: [], estimated_base_reduction: 0 },
    ]);
  }

  function removeCandidate(i: number) {
    setCandidates((prev) => prev.filter((_, idx) => idx !== i));
  }

  async function submit() {
    const valid = candidates.filter((c) => c.remediation_id.trim());
    if (valid.length === 0) {
      setError("At least one candidate remediation with an ID is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const plan = await generatePlan({ candidate_remediations: valid, plan_budget: planBudget });
      onGenerated(plan);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate plan");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal
      title="Generate Exposure Reduction Plan"
      onClose={onClose}
      contentClassName="w-full max-w-2xl rounded-xl border border-gray-800 bg-gray-900 p-5"
    >
      <FormField label="Plan Budget (max remediations selected)">
        <input
          type="number"
          value={planBudget}
          onChange={(e) => setPlanBudget(Number(e.target.value))}
          className="w-32 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />
      </FormField>

      <Panel title="Candidate Remediations" className="mt-4">
        <div className="max-h-64 space-y-3 overflow-y-auto">
          {candidates.map((c, i) => (
            <div key={i} className="grid grid-cols-12 gap-2">
              <input
                aria-label={`Remediation ID for candidate ${i + 1}`}
                placeholder="Remediation ID"
                value={c.remediation_id}
                onChange={(e) => updateCandidate(i, { remediation_id: e.target.value })}
                className="col-span-4 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
              />
              <input
                aria-label={`Affected asset refs for candidate ${i + 1}`}
                placeholder="Affected asset refs (comma-separated)"
                value={c.affected_asset_refs.join(",")}
                onChange={(e) =>
                  updateCandidate(i, {
                    affected_asset_refs: e.target.value.split(",").map((s) => s.trim()).filter(Boolean),
                  })
                }
                className="col-span-5 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
              />
              <input
                aria-label={`Base reduction for candidate ${i + 1}`}
                type="number"
                step="0.1"
                placeholder="Base reduction"
                value={c.estimated_base_reduction}
                onChange={(e) => updateCandidate(i, { estimated_base_reduction: Number(e.target.value) })}
                className="col-span-2 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
              />
              <button
                type="button"
                aria-label={`Remove candidate ${i + 1}`}
                onClick={() => removeCandidate(i)}
                disabled={candidates.length === 1}
                className="col-span-1 rounded-md border border-gray-700 px-1 py-1.5 text-xs text-gray-400 hover:text-red-300 disabled:opacity-30"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addCandidate}
          className="mt-3 rounded-md border border-gray-700 px-3 py-1 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
        >
          + Add Candidate
        </button>
      </Panel>

      {error && (
        <p role="alert" className="mt-3 text-xs text-red-400">
          {error}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
          Cancel
        </button>
        <button
          disabled={busy}
          onClick={submit}
          className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
        >
          {busy ? "Generating…" : "Generate Plan"}
        </button>
      </div>
    </FormModal>
  );
}
