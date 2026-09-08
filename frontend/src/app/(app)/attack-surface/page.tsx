"use client";

import Link from "next/link";
import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  fmtTime,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  evaluateCorrelations,
  getAssetExposureSummary,
  getAttackSurfaceSummary,
  listSecurityCorrelations,
  type AssetExposureSummary,
  type SecurityCorrelation,
} from "@/lib/securityCorrelations";

function displayEnum(value: string | undefined | null): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-950 text-red-400",
  high: "bg-orange-950 text-orange-400",
  medium: "bg-amber-950 text-amber-400",
  low: "bg-yellow-950 text-yellow-300",
  informational: "bg-gray-800 text-gray-400",
};

function severityBadge(severity: string): string {
  return SEVERITY_STYLES[severity] ?? "bg-gray-800 text-gray-400";
}

export default function AttackSurfacePage() {
  const summary = useAsync(() => getAttackSurfaceSummary(), []);
  const [selected, setSelected] = useState<SecurityCorrelation | null>(null);
  const [assetDetail, setAssetDetail] = useState<AssetExposureSummary | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [evalError, setEvalError] = useState("");
  const [lifecycle, setLifecycle] = useState("");
  const [ruleId, setRuleId] = useState("");

  const correlations = useAsync(
    () =>
      listSecurityCorrelations({
        lifecycle: lifecycle || undefined,
        stable_rule_id: ruleId || undefined,
      }),
    [lifecycle, ruleId]
  );

  function reloadAll() {
    summary.reload();
    correlations.reload();
  }

  async function handleEvaluate() {
    setEvaluating(true);
    setEvalError("");
    try {
      await evaluateCorrelations();
      reloadAll();
    } catch {
      setEvalError("Failed to run correlation evaluation.");
    } finally {
      setEvaluating(false);
    }
  }

  async function openCorrelation(c: SecurityCorrelation) {
    setSelected(c);
    setAssetDetail(null);
    if (c.entity_ids.length > 0) {
      try {
        const detail = await getAssetExposureSummary(c.entity_ids[0]);
        setAssetDetail(detail);
      } catch {
        setAssetDetail(null);
      }
    }
  }

  const columns: ConsoleColumn<SecurityCorrelation>[] = [
    {
      key: "rule",
      header: "Rule",
      width: "16%",
      render: (c) => (
        <span className="rounded bg-gray-800 px-2 py-0.5 font-mono text-[11px] text-gray-400">
          {c.stable_rule_id}
        </span>
      ),
    },
    {
      key: "evidence_state",
      header: "Evidence State",
      width: "12%",
      render: (c) => (
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[11px] text-gray-400">
          {displayEnum(c.evidence_state)}
        </span>
      ),
    },
    {
      key: "lifecycle",
      header: "Lifecycle",
      width: "10%",
      render: (c) => (
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[11px] text-gray-400">
          {c.lifecycle === "resolved" ? "RESOLVED" : "ACTIVE"}
        </span>
      ),
    },
    {
      key: "title",
      header: "Title",
      width: "32%",
      render: (c) => <span className="text-gray-200">{c.title}</span>,
    },
    {
      key: "counts",
      header: "Entities / Conditions",
      width: "16%",
      render: (c) => (
        <span className="text-gray-400">
          {c.entity_ids.length} entit{c.entity_ids.length === 1 ? "y" : "ies"} ·{" "}
          {c.condition_ids.length} condition{c.condition_ids.length === 1 ? "" : "s"}
        </span>
      ),
    },
    {
      key: "last_observed",
      header: "Last Observed",
      width: "14%",
      render: (c) => <span className="text-gray-400">{fmtTime(c.last_observed_at)}</span>,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Attack Surface"
        subtitle="Deterministic correlations across already-canonical security conditions — evidence-backed exposure concentration, never exploitability, compromise, or a magic risk score. Relationship context lives in the Security Graph, labeled as an Exposure Relationship Path, never an attack path."
        actions={
          <div className="flex shrink-0 items-center gap-2">
            <Link
              href="/attack-surface/assets"
              className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-blue-800 hover:text-blue-300"
            >
              Asset Register →
            </Link>
            <button
              onClick={handleEvaluate}
              disabled={evaluating}
              className="rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 disabled:opacity-50"
            >
              {evaluating ? "Evaluating…" : "Run Evaluation"}
            </button>
          </div>
        }
      />

      {evalError ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {evalError}
        </div>
      ) : null}

      <div className="mt-6">
        <AsyncContent state={summary}>
          {(s) => (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-3">
              <KpiTile label="Assets w/ active conditions" value={s.assets_with_active_conditions} />
              <KpiTile
                label="Assets w/ multiple conditions"
                value={s.assets_with_multiple_active_conditions}
              />
              <KpiTile label="Active correlations" value={s.active_correlations} />
            </div>
          )}
        </AsyncContent>
      </div>

      <div className="mt-6 flex flex-wrap gap-3">
        <select
          value={lifecycle}
          onChange={(e) => setLifecycle(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All lifecycle states</option>
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          value={ruleId}
          onChange={(e) => setRuleId(e.target.value)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300"
        >
          <option value="">All rules</option>
          <option value="PUBLIC_SENSITIVE_SERVICE_CONTEXT">Public sensitive service context</option>
          <option value="MULTIPLE_SECURITY_CONDITIONS_ON_ASSET">Multiple conditions on asset</option>
        </select>
      </div>

      <div className="mt-6">
        <AsyncContent
          state={correlations}
          empty={(rows) => rows.length === 0}
          emptyLabel="No correlations match the current filters. Run an evaluation if conditions exist."
        >
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows}
              rowKey={(c) => c.id}
              onRowClick={(c) => openCorrelation(c)}
              selectedKey={selected?.id ?? null}
              emptyLabel="No correlations match the current filters. Run an evaluation if conditions exist."
            />
          )}
        </AsyncContent>
      </div>

      {selected && (
        <InvestigationDrawer
          open
          onClose={() => setSelected(null)}
          title={selected.title}
          subtitle={`${selected.stable_rule_id} · v${selected.rule_version}`}
          entityId={selected.id}
          fields={correlationFields(selected, assetDetail)}
          links={selected.entity_ids.map((id) => ({
            label: `Asset ${id.slice(0, 8)}… →`,
            href: `/attack-surface/assets?highlight=${id}`,
          }))}
        />
      )}
    </div>
  );
}

function correlationFields(
  selected: SecurityCorrelation,
  assetDetail: AssetExposureSummary | null
): DrawerField[] {
  const fields: DrawerField[] = [
    { label: "Evidence State", value: displayEnum(selected.evidence_state) },
    { label: "Summary", value: selected.summary },
    { label: "Operator Action", value: selected.operator_action },
    { label: "Affected Entities", value: selected.entity_ids.join(", ") || "—" },
    { label: "Source Conditions", value: selected.condition_ids.join(", ") || "—" },
    { label: "First Observed", value: fmtTime(selected.first_observed_at) },
    { label: "Last Observed", value: fmtTime(selected.last_observed_at) },
    { label: "Lifecycle", value: selected.lifecycle === "resolved" ? "RESOLVED" : "ACTIVE" },
  ];
  if (assetDetail) {
    fields.push({
      label: `Asset Exposure — ${assetDetail.asset_name}`,
      value: (
        <div className="flex flex-wrap gap-2">
          <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
            {displayEnum(assetDetail.external_classification)}
          </span>
          <span className={`rounded px-2 py-0.5 text-xs ${severityBadge(assetDetail.highest_active_severity)}`}>
            {displayEnum(assetDetail.highest_active_severity)}
          </span>
          <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
            {assetDetail.active_condition_count} active conditions
          </span>
          <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
            {assetDetail.sensitive_service_count} sensitive services
          </span>
        </div>
      ),
    });
  }
  return fields;
}
