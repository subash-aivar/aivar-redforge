"use client";

import { useState } from "react";
import {
  configureProvider,
  enrichIp,
  exportAttackNavigatorLayer,
  getIndicatorEnrichments,
  getProviderHealth,
  getSyncStatus,
  listCatalogIndicators,
  listIndicators,
  listProviders,
  PROVIDER_LABELS,
  runCorrelation,
  triggerSync,
  type CatalogIndicator,
  type Enrichment,
  type Indicator,
  type SyncJobStatus,
} from "@/lib/threatIntel";
import { ApiError } from "@/lib/api";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  Panel,
  PageHeader,
  fmtTime,
  useAsync,
  type DrawerField,
} from "@/components/cc";

const STATUS_TONE: Record<string, string> = {
  not_configured: "border-gray-700 bg-gray-800/60 text-gray-400",
  healthy: "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  degraded: "border-amber-800 bg-amber-950/50 text-amber-300",
  rate_limited: "border-amber-800 bg-amber-950/50 text-amber-300",
  quota_exhausted: "border-amber-800 bg-amber-950/50 text-amber-300",
  auth_failure: "border-red-800 bg-red-950/60 text-red-300",
  circuit_open: "border-red-800 bg-red-950/60 text-red-300",
};

function HealthPill({ status }: { status: string }) {
  const tone = STATUS_TONE[status] ?? STATUS_TONE.not_configured;
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${tone}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

function ProviderRow({
  provider,
  health,
  onChanged,
}: {
  provider: { provider_name: string; enabled: boolean; is_optional_disclaimer_required: boolean; credential_ref: string | null };
  health: { status: string; circuit_state: string; last_success_at: string | null } | undefined;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credentialRef, setCredentialRef] = useState(provider.credential_ref ?? "");

  async function toggle(enabled: boolean) {
    setBusy(true);
    setError(null);
    try {
      await configureProvider(provider.provider_name, {
        enabled,
        allowed_indicator_types: ["ip"],
        credential_ref: credentialRef || null,
      });
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to update provider");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-2 border-b border-gray-800 py-3 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <span className="w-52 shrink-0 text-sm text-gray-200">
          {PROVIDER_LABELS[provider.provider_name] ?? provider.provider_name}
        </span>
        {provider.is_optional_disclaimer_required && (
          <span className="rounded border border-amber-800 bg-amber-950/40 px-1.5 py-0.5 text-[10px] uppercase text-amber-300">
            compliance disclaimer
          </span>
        )}
        <HealthPill status={health?.status ?? "not_configured"} />
      </div>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={credentialRef}
          onChange={(e) => setCredentialRef(e.target.value)}
          placeholder="Env var name (e.g. ABUSEIPDB_API_KEY)"
          className="w-64 rounded-md border border-gray-800 bg-gray-950/80 px-2 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
        />
        <button
          type="button"
          disabled={busy}
          onClick={() => toggle(!provider.enabled)}
          className={`rounded-md border px-2.5 py-1 text-xs font-semibold disabled:opacity-40 ${
            provider.enabled
              ? "border-gray-800 text-gray-400 hover:border-red-900 hover:text-red-300"
              : "border-emerald-800 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-950/60"
          }`}
        >
          {provider.enabled ? "Disable" : "Enable"}
        </button>
        {error && <span className="text-[11px] text-red-400">{error}</span>}
      </div>
    </div>
  );
}

export default function ThreatIntelligencePage() {
  const providers = useAsync(listProviders, []);
  const health = useAsync(getProviderHealth, []);
  const indicators = useAsync(() => listIndicators(50, 0), []);
  const techniques = useAsync(() => listCatalogIndicators("technique", 80), []);
  const vulnerabilities = useAsync(() => listCatalogIndicators("vulnerability", 40), []);
  const actors = useAsync(() => listCatalogIndicators("group", 40), []);
  const syncJobs = useAsync(getSyncStatus, []);

  const [lookupIp, setLookupIp] = useState("");
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupResult, setLookupResult] = useState<Record<string, unknown> | null>(null);
  const [correlateBusy, setCorrelateBusy] = useState(false);
  const [correlateResult, setCorrelateResult] = useState<{ indicators_checked: number; matches_found: number } | null>(null);
  const [navBusy, setNavBusy] = useState(false);
  const [syncBusy, setSyncBusy] = useState<string | null>(null);

  const [selectedIndicator, setSelectedIndicator] = useState<Indicator | null>(null);
  const enrichments = useAsync<Enrichment[]>(
    () => (selectedIndicator ? getIndicatorEnrichments(selectedIndicator.id) : Promise.resolve([])),
    [selectedIndicator?.id],
  );

  const healthByProvider = new Map((health.data ?? []).map((h) => [h.provider_name, h]));

  async function downloadNavigator() {
    setNavBusy(true);
    try {
      const layer = await exportAttackNavigatorLayer();
      const blob = new Blob([JSON.stringify(layer, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "redforge-attack-navigator-layer.json";
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setNavBusy(false);
    }
  }

  async function runSync(jobKey: string) {
    setSyncBusy(jobKey);
    try {
      await triggerSync(jobKey);
      syncJobs.reload();
      techniques.reload();
      vulnerabilities.reload();
      actors.reload();
    } finally {
      setSyncBusy(null);
    }
  }

  function heatTone(item: CatalogIndicator): string {
    const c = item.confidence ?? "LOW";
    if (c === "VERY_HIGH" || c === "HIGH") return "bg-red-900/50 border-red-800 text-red-200";
    if (c === "MEDIUM") return "bg-amber-950/40 border-amber-900 text-amber-200";
    return "bg-gray-900 border-gray-800 text-gray-400";
  }

  async function doLookup() {
    if (!lookupIp.trim()) return;
    setLookupBusy(true);
    setLookupError(null);
    setLookupResult(null);
    try {
      const result = await enrichIp(lookupIp.trim());
      setLookupResult(result as unknown as Record<string, unknown>);
      indicators.reload();
    } catch (e) {
      setLookupError(e instanceof ApiError ? e.message : "Lookup failed");
    } finally {
      setLookupBusy(false);
    }
  }

  async function doCorrelate() {
    setCorrelateBusy(true);
    try {
      const result = await runCorrelation(50);
      setCorrelateResult(result);
    } finally {
      setCorrelateBusy(false);
    }
  }

  const drawerFields: DrawerField[] = enrichments.data
    ? enrichments.data.flatMap((e) => [
        { label: `${e.provider_name} · ${e.kind}`, value: e.success ? "success" : `failed (${e.error_category ?? "unknown"})` },
        ...(e.success && Object.keys(e.data).length > 0
          ? Object.entries(e.data).map(([k, v]) => ({ label: `  ${k}`, value: String(v ?? "—") }))
          : [{ label: "  evidence", value: "none found (honest negative)" }]),
        { label: "  fetched_at", value: fmtTime(e.fetched_at) },
      ])
    : [];

  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        subtitle="IP reputation, geolocation, ASN/RDAP, and IOC correlation — every value traces to a real provider call or a real local dataset lookup. Reputation is evidence, not a verdict; geolocation is approximate."
      />

      <div className="mb-4 grid grid-cols-3 gap-3">
        <KpiTile label="Providers enabled" value={(providers.data ?? []).filter((p) => p.enabled).length} />
        <KpiTile
          label="Providers healthy"
          value={(health.data ?? []).filter((h) => h.status === "healthy").length}
          tone="ok"
        />
        <KpiTile label="Indicators tracked" value={indicators.data?.length ?? 0} />
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel
          title="MITRE technique heatmap"
          right={
            <button
              type="button"
              disabled={navBusy}
              onClick={downloadNavigator}
              className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-300 hover:border-red-900"
            >
              {navBusy ? "Exporting…" : "ATT&CK Navigator JSON"}
            </button>
          }
        >
          <AsyncContent
            state={techniques}
            empty={(rows) => rows.length === 0}
            emptyLabel="No fused techniques yet — run attack_technique_sync / fusion."
          >
            {(rows) => (
              <div className="flex max-h-56 flex-wrap gap-1 overflow-auto">
                {rows.map((t) => (
                  <span
                    key={t.id}
                    title={`${t.display_name} · ${t.confidence ?? "NO_EVIDENCE"}`}
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${heatTone(t)}`}
                  >
                    {t.canonical_key.replace(/^technique:/i, "").toUpperCase()}
                  </span>
                ))}
              </div>
            )}
          </AsyncContent>
        </Panel>

        <Panel title="CVE panel">
          <AsyncContent
            state={vulnerabilities}
            empty={(rows) => rows.length === 0}
            emptyLabel="No fused vulnerabilities in catalog."
          >
            {(rows) => (
              <ul className="max-h-56 space-y-1 overflow-auto text-xs">
                {rows.map((v) => (
                  <li key={v.id} className="flex justify-between gap-2 border-b border-gray-900 py-1">
                    <span className="font-mono text-gray-200">{v.display_name}</span>
                    <span className="text-gray-500">
                      {v.metadata.is_kev === "True" ? "KEV" : v.confidence ?? "—"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Threat actor profiles">
          <AsyncContent
            state={actors}
            empty={(rows) => rows.length === 0}
            emptyLabel="No fused group/actor stubs yet (from ATT&CK relationships)."
          >
            {(rows) => (
              <ul className="max-h-56 space-y-1 overflow-auto text-xs">
                {rows.map((a) => (
                  <li key={a.id} className="border-b border-gray-900 py-1 text-gray-200">
                    {a.display_name}
                    <span className="ml-2 text-gray-600">{a.confidence ?? "—"}</span>
                  </li>
                ))}
              </ul>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mb-4">
        <Panel title="Intelligence sync jobs">
          <AsyncContent
            state={syncJobs}
            empty={(rows) => rows.length === 0}
            emptyLabel="No sync jobs recorded yet."
          >
            {(rows: SyncJobStatus[]) => (
              <div className="space-y-2">
                {rows.map((job) => (
                  <div
                    key={job.job_key}
                    className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-900 py-2 text-xs"
                  >
                    <div>
                      <span className="font-mono text-gray-200">{job.job_key}</span>
                      <span className="ml-2 text-gray-500">{job.last_status}</span>
                      {job.last_error && (
                        <span className="ml-2 text-red-400">{job.last_error}</span>
                      )}
                    </div>
                    <button
                      type="button"
                      disabled={syncBusy === job.job_key}
                      onClick={() => runSync(job.job_key)}
                      className="rounded border border-gray-800 px-2 py-1 text-gray-300 hover:border-red-900 disabled:opacity-40"
                    >
                      {syncBusy === job.job_key ? "Running…" : "Trigger"}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <Panel title="On-demand IP lookup">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={lookupIp}
            onChange={(e) => setLookupIp(e.target.value)}
            placeholder="Public IP (e.g. 8.8.8.8) — private/internal IPs are rejected before any provider is called"
            className="w-96 max-w-full rounded-md border border-gray-800 bg-gray-950/80 px-2.5 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
          />
          <button
            type="button"
            disabled={lookupBusy}
            onClick={doLookup}
            className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 disabled:opacity-40"
          >
            {lookupBusy ? "Checking…" : "Enrich"}
          </button>
          {lookupError && <span className="text-xs text-red-400">{lookupError}</span>}
        </div>
        {lookupResult && (
          <pre className="mt-3 max-h-64 overflow-auto rounded-lg border border-gray-800 bg-gray-950/60 p-3 text-[11px] text-gray-300">
            {JSON.stringify(lookupResult, null, 2)}
          </pre>
        )}
      </Panel>

      <div className="mt-4">
        <Panel
          title="Provider configuration & health"
          right={<span className="text-[11px] text-gray-600">disabled by default — zero egress until an admin enables a provider</span>}
        >
          <AsyncContent state={providers}>
            {(rows) => (
              <div>
                {rows.map((p) => (
                  <ProviderRow
                    key={p.provider_name}
                    provider={p}
                    health={healthByProvider.get(p.provider_name)}
                    onChanged={() => {
                      providers.reload();
                      health.reload();
                    }}
                  />
                ))}
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel
          title="IOC correlation"
          right={
            <button
              type="button"
              disabled={correlateBusy}
              onClick={doCorrelate}
              className="rounded-md border border-gray-800 px-2.5 py-1 text-[11px] text-gray-300 hover:border-red-900 hover:text-red-300 disabled:opacity-40"
            >
              {correlateBusy ? "Running…" : "Run correlation over recent indicators"}
            </button>
          }
        >
          {correlateResult ? (
            <p className="text-sm text-gray-300">
              Checked {correlateResult.indicators_checked} already-observed indicator(s) against configured IOC sources —{" "}
              {correlateResult.matches_found} match(es) found. Never invents an indicator to check.
            </p>
          ) : (
            <p className="text-sm text-gray-500">
              Correlates RedForge&apos;s own already-observed indicators against configured IOC sources (AlienVault OTX,
              abuse.ch if enabled). Run it to see results.
            </p>
          )}
        </Panel>
      </div>

      <div className="mt-4">
        <Panel title="Recently enriched indicators">
          <AsyncContent
            state={indicators}
            empty={(rows) => rows.length === 0}
            emptyLabel="No indicators enriched yet. Use the lookup above, or let real network/asset discovery feed real public IPs here."
          >
            {(rows) => (
              <DataConsole
                rows={rows}
                rowKey={(r) => r.id}
                onRowClick={setSelectedIndicator}
                selectedKey={selectedIndicator?.id ?? null}
                columns={[
                  { key: "indicator", header: "Indicator", render: (r) => <span className="font-mono text-gray-200">{r.indicator}</span> },
                  { key: "type", header: "Type", width: "80px", render: (r) => r.indicator_type },
                  { key: "first", header: "First seen", width: "160px", render: (r) => fmtTime(r.first_seen_at) },
                  { key: "last", header: "Last seen", width: "160px", render: (r) => fmtTime(r.last_seen_at) },
                ]}
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <InvestigationDrawer
        open={selectedIndicator !== null}
        onClose={() => setSelectedIndicator(null)}
        title={selectedIndicator?.indicator ?? ""}
        subtitle={selectedIndicator ? `Indicator · ${selectedIndicator.indicator_type}` : ""}
        fields={drawerFields}
      />
    </div>
  );
}
