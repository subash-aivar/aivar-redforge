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
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  ML_MODEL_TYPES,
  listModels,
  getModel,
  getGovernanceHistory,
  scheduleTraining,
  promoteModel,
  deprecateModel,
  checkDrift,
  getSignals,
  runInference,
  type ModelSummary,
  type ModelDetail,
  type SignalsResult,
} from "@/lib/mlPipeline";
import { getMe } from "@/lib/auth";

export default function MLPipelinePage() {
  const models = useAsync(() => listModels(), []);
  const [tab, setTab] = useState<"models" | "signals" | "inference">("models");
  const [selected, setSelected] = useState<ModelSummary | null>(null);
  const [showTrain, setShowTrain] = useState(false);

  return (
    <>
      <PageHeader
        title="ML Pipeline"
        subtitle="Predictive risk model training, governance, drift monitoring, and inference"
        actions={
          <button
            onClick={() => setShowTrain(true)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
          >
            Train Model
          </button>
        }
      />

      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["models", "signals", "inference"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t === "models" ? "Models" : t === "signals" ? "Risk Signals" : "Inference Tester"}
          </button>
        ))}
      </div>

      {tab === "models" && (
        <ModelsTab state={models} onSelect={setSelected} />
      )}
      {tab === "signals" && <SignalsTab />}
      {tab === "inference" && <InferenceTab />}

      {selected && (
        <ModelDetailDrawer
          modelId={selected.model_id}
          onClose={() => setSelected(null)}
          onChanged={() => models.reload()}
        />
      )}

      {showTrain && (
        <TrainModelModal
          onClose={() => setShowTrain(false)}
          onScheduled={() => {
            models.reload();
            setShowTrain(false);
          }}
        />
      )}
    </>
  );
}

function ModelsTab({
  state,
  onSelect,
}: {
  state: ReturnType<typeof useAsync<ModelSummary[]>>;
  onSelect: (m: ModelSummary) => void;
}) {
  const cols: ConsoleColumn<ModelSummary>[] = [
    { key: "type", header: "Model Type", width: "30%", render: (r) => <span className="text-gray-200">{r.model_type.replace(/_/g, " ")}</span> },
    { key: "status", header: "Status", width: "20%", render: (r) => <StatusPill status={r.status} /> },
    { key: "id", header: "Model ID", width: "50%", render: (r) => <span className="font-mono text-[11px] text-gray-500">{r.model_id}</span> },
  ];
  return (
    <AsyncContent state={state} empty={(d) => d.length === 0} emptyLabel="No models trained yet.">
      {(list) => (
        <>
          <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <KpiTile label="Total Models" value={list.length} />
            <KpiTile label="Deployed" value={list.filter((m) => m.status === "DEPLOYED").length} tone="ok" />
            <KpiTile label="Training" value={list.filter((m) => m.status === "TRAINING").length} tone="warning" />
            <KpiTile label="Failed" value={list.filter((m) => m.status === "FAILED").length} tone="danger" />
          </div>
          <DataConsole columns={cols} rows={list} rowKey={(r) => r.model_id} onRowClick={onSelect} emptyLabel="No models trained yet." />
        </>
      )}
    </AsyncContent>
  );
}

function ModelDetailDrawer({
  modelId,
  onClose,
  onChanged,
}: {
  modelId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const detail = useAsync(() => getModel(modelId), [modelId]);
  const governance = useAsync(() => getGovernanceHistory(modelId), [modelId]);
  const [busy, setBusy] = useState(false);
  const [driftInput, setDriftInput] = useState("");
  const [driftResult, setDriftResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handlePromote(m: ModelDetail) {
    setBusy(true);
    setError(null);
    try {
      const me = await getMe().catch(() => null);
      await promoteModel(m.model_id, me?.email || "console");
      detail.reload();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to promote model");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeprecate(m: ModelDetail) {
    setBusy(true);
    setError(null);
    try {
      const me = await getMe().catch(() => null);
      await deprecateModel(m.model_id, me?.email || "console");
      detail.reload();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to deprecate model");
    } finally {
      setBusy(false);
    }
  }

  async function handleDriftCheck() {
    const values = driftInput.split(",").map((s) => parseFloat(s.trim())).filter((n) => !isNaN(n));
    if (values.length === 0) {
      setError("Enter comma-separated numeric values.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await checkDrift(modelId, values);
      setDriftResult(`PSI: ${r.psi.toFixed(4)} — ${r.severe ? "SEVERE DRIFT" : "within tolerance"}. Model status: ${r.status}.`);
      detail.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Drift check failed");
    } finally {
      setBusy(false);
    }
  }

  if (detail.loading || !detail.data) {
    return (
      <InvestigationDrawer
        open
        title="Model Detail"
        onClose={onClose}
        fields={[{ label: "Loading", value: detail.forbidden ? "You don't have permission to view this model." : "Loading model detail…" }]}
      />
    );
  }

  const m = detail.data;
  const fields: DrawerField[] = [
    { label: "Model Type", value: m.model_type.replace(/_/g, " ") },
    { label: "Algorithm", value: m.algorithm },
    { label: "Status", value: <StatusPill status={m.status} /> },
    { label: "PSI Score", value: m.psi_score != null ? m.psi_score.toFixed(4) : "Not computed" },
    { label: "Artifact Hash", value: m.artifact_hash ? <span className="font-mono text-[11px]">{m.artifact_hash}</span> : "Not trained" },
    {
      label: "Accuracy Metrics",
      value: Object.keys(m.accuracy_metrics).length > 0
        ? (
          <div className="space-y-1">
            {Object.entries(m.accuracy_metrics).map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs">
                <span className="text-gray-500">{k}</span>
                <span className="text-gray-200">{v.toFixed(4)}</span>
              </div>
            ))}
          </div>
        )
        : "No metrics recorded",
    },
    {
      label: "Lifecycle Actions",
      value: (
        <div className="flex gap-2">
          <button
            onClick={() => handlePromote(m)}
            disabled={busy || m.status === "DEPLOYED"}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
          >
            Promote
          </button>
          <button
            onClick={() => handleDeprecate(m)}
            disabled={busy || m.status === "DEPRECATED"}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
          >
            Deprecate
          </button>
        </div>
      ),
    },
    {
      label: "Drift Check (Admin)",
      value: (
        <div className="space-y-2">
          <input
            value={driftInput}
            onChange={(e) => setDriftInput(e.target.value)}
            placeholder="Actual values, comma-separated"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
          />
          <button
            onClick={handleDriftCheck}
            disabled={busy}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
          >
            Run Drift Check
          </button>
          {driftResult && <p className="text-xs text-emerald-400">{driftResult}</p>}
        </div>
      ),
    },
    {
      label: "Governance History",
      value: (
        <AsyncContent state={governance} empty={(d) => d.length === 0} emptyLabel="No governance events recorded.">
          {(rows) => (
            <div className="max-h-48 space-y-1 overflow-y-auto">
              {rows.map((r, i) => (
                <pre key={i} className="whitespace-pre-wrap text-[10px] text-gray-500">{JSON.stringify(r)}</pre>
              ))}
            </div>
          )}
        </AsyncContent>
      ),
    },
    ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
  ];

  return (
    <InvestigationDrawer
      open
      title={m.model_type.replace(/_/g, " ")}
      subtitle={m.model_id}
      onClose={onClose}
      fields={fields}
    />
  );
}

function SignalsTab() {
  const [assetRefId, setAssetRefId] = useState("");
  const [signalType, setSignalType] = useState("");
  const [result, setResult] = useState<SignalsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function search() {
    setLoading(true);
    setError(null);
    try {
      const r = await getSignals({
        asset_ref_id: assetRefId.trim() || undefined,
        signal_type: signalType.trim() || undefined,
      });
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Signal lookup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="mb-4 flex gap-2">
        <input
          value={assetRefId}
          onChange={(e) => setAssetRefId(e.target.value)}
          placeholder="Asset Reference ID (UUID)"
          className="w-64 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />
        <input
          value={signalType}
          onChange={(e) => setSignalType(e.target.value)}
          placeholder="Signal Type"
          className="w-48 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        />
        <button
          onClick={search}
          disabled={loading}
          className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
        >
          {loading ? "Searching…" : "Search"}
        </button>
      </div>
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      {result && (
        <Panel title={`Signals (${result.status})`}>
          {result.reason && <p className="mb-2 text-xs text-amber-400">{result.reason.replace(/_/g, " ")}</p>}
          {result.signals.length === 0 ? (
            <p className="text-sm text-gray-500">No signals found.</p>
          ) : (
            <div className="divide-y divide-gray-800">
              {result.signals.map((s, i) => (
                <div key={i} className="flex items-center justify-between px-2 py-2">
                  <span className="font-mono text-xs text-gray-400">{s.asset_ref_id}</span>
                  <span className="text-xs text-gray-500">{s.signal_type}</span>
                  <span className="font-semibold text-gray-200">{s.score.toFixed(3)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}
    </>
  );
}

function InferenceTab() {
  const [modelType, setModelType] = useState(ML_MODEL_TYPES[0]);
  const [assetsJson, setAssetsJson] = useState('[{"asset_ref_id": "example-asset-1"}]');
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const assets = JSON.parse(assetsJson);
      if (!Array.isArray(assets)) throw new Error("Assets must be a JSON array.");
      const r = await runInference({ model_type: modelType, assets });
      setResult(JSON.stringify(r, null, 2));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Inference failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Run Inference">
      <label className="mb-1 block text-xs text-gray-500">Model Type</label>
      <select
        value={modelType}
        onChange={(e) => setModelType(e.target.value as typeof modelType)}
        className="mb-3 w-64 rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
      >
        {ML_MODEL_TYPES.map((t) => (
          <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
        ))}
      </select>
      <label className="mb-1 block text-xs text-gray-500">Assets (JSON array)</label>
      <textarea
        value={assetsJson}
        onChange={(e) => setAssetsJson(e.target.value)}
        rows={4}
        className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 font-mono text-xs text-gray-200"
      />
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      <button
        onClick={run}
        disabled={busy}
        className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
      >
        {busy ? "Running…" : "Run Inference"}
      </button>
      {result && (
        <pre className="mt-4 max-h-64 overflow-auto rounded bg-gray-950 p-3 text-[11px] text-gray-300">{result}</pre>
      )}
    </Panel>
  );
}

function TrainModelModal({
  onClose,
  onScheduled,
}: {
  onClose: () => void;
  onScheduled: () => void;
}) {
  const [modelType, setModelType] = useState(ML_MODEL_TYPES[0]);
  const [datasetId, setDatasetId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await scheduleTraining({ model_type: modelType, dataset_id: datasetId.trim() || undefined });
      onScheduled();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to schedule training");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="Schedule Model Training" onClose={onClose}>
      <div className="space-y-3">
        <FormField label="Model Type">
          <select
            value={modelType}
            onChange={(e) => setModelType(e.target.value as typeof modelType)}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          >
            {ML_MODEL_TYPES.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
            ))}
          </select>
        </FormField>
        <FormField
          label="Dataset ID (optional)"
          hint="If no training rows are supplied, synthetic separable data is used to validate the pipeline."
        >
          <input
            value={datasetId}
            onChange={(e) => setDatasetId(e.target.value)}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
      </div>
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
          {busy ? "Scheduling…" : "Train"}
        </button>
      </div>
    </FormModal>
  );
}
