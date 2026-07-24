"use client";

import { useMemo, useState } from "react";
import {
  AsyncContent,
  DataConsole,
  EvaluatedRiskScore,
  EvaluationStatePill,
  FilterChip,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  SearchInput,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { getMe } from "@/lib/auth";
import {
  createDefaultVaultBackend,
  disableConnector,
  getHealthHistory,
  hasCapability,
  listAssetRelationships,
  listAssets,
  listCatalog,
  listConnectors,
  listDiscoveryHistory,
  listVaultBackends,
  registerConnectorWithCredential,
  runDiscovery,
  testConnection,
  type AssetRelationship,
  type ConnectorPlugin,
  type ConnectorRegistration,
  type DiscoveredAsset,
  type SyncRun,
} from "@/lib/integrations";

type Tab = "connectors" | "assets" | "history";

export default function IntegrationsPage() {
  const [tab, setTab] = useState<Tab>("connectors");
  const catalog = useAsync(() => listCatalog(), []);
  const connectors = useAsync(() => listConnectors(), []);

  const [wizardPlugin, setWizardPlugin] = useState<ConnectorPlugin | null>(null);
  const [selectedConnector, setSelectedConnector] = useState<ConnectorRegistration | null>(null);

  function reload() {
    catalog.reload();
    connectors.reload();
  }

  const catalogColumns: ConsoleColumn<ConnectorPlugin>[] = [
    { key: "name", header: "Connector", width: "26%", render: (r) => (
      <span className="text-gray-200">{r.display_name}</span>
    ) },
    { key: "category", header: "Category", width: "18%", render: (r) => r.category },
    { key: "auth", header: "Auth Model", width: "26%", render: (r) => r.auth_model.replace(/_/g, " ") },
    { key: "action", header: "", width: "30%", render: (r) => (
      <button
        type="button"
        onClick={() => setWizardPlugin(r)}
        className="rounded-md border border-red-800 bg-red-950/40 px-2.5 py-1 text-[11px] font-semibold text-red-300 hover:bg-red-950/70"
      >
        Configure
      </button>
    ) },
  ];

  const registrationColumns: ConsoleColumn<ConnectorRegistration>[] = [
    { key: "name", header: "Connector", width: "24%", render: (r) => (
      <span className="text-gray-200">{r.display_name}</span>
    ) },
    { key: "type", header: "Type", width: "18%", render: (r) => r.connector_type },
    { key: "status", header: "Status", width: "16%", render: (r) => <StatusPill status={r.status} /> },
    { key: "circuit", header: "Circuit", width: "16%", render: (r) => r.circuit_state },
    { key: "vault", header: "Vault Key", width: "26%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-500">{r.credential_vault_key.slice(0, 12)}…</span>
    ) },
  ];

  return (
    <>
      <PageHeader
        title="Integrations"
        subtitle="Connector catalog, credentials (via Credential Vault), and health monitoring"
        actions={
          <button
            type="button"
            onClick={reload}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-6 flex gap-2 border-b border-gray-800 pb-px">
        {(
          [
            { key: "connectors", label: "Connectors" },
            { key: "assets", label: "Asset Inventory" },
            { key: "history", label: "Discovery Timeline" },
          ] as { key: Tab; label: string }[]
        ).map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`px-3 py-2 text-xs font-semibold uppercase tracking-wide ${
              tab === t.key
                ? "border-b-2 border-red-600 text-red-300"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "connectors" && (
        <>
          <AsyncContent state={connectors} emptyLabel="No connectors registered yet.">
            {(rows) => (
              <div className="mb-6 grid gap-4 sm:grid-cols-3">
                <KpiTile label="Registered Connectors" value={rows.length} />
                <KpiTile
                  label="Healthy"
                  value={rows.filter((r) => r.status === "HEALTHY" || r.status === "REGISTERED").length}
                  tone="ok"
                />
                <KpiTile
                  label="Unhealthy / Degraded"
                  value={rows.filter((r) => r.status === "UNHEALTHY" || r.status === "DEGRADED").length}
                  tone={rows.some((r) => r.status === "UNHEALTHY") ? "danger" : "warning"}
                />
              </div>
            )}
          </AsyncContent>

          <Panel title="Registered Connectors" className="mb-6">
            <AsyncContent state={connectors} emptyLabel="No connectors registered yet.">
              {(rows) => (
                <DataConsole
                  columns={registrationColumns}
                  rows={rows}
                  rowKey={(r) => r.connector_id}
                  onRowClick={(r) => setSelectedConnector(r)}
                  selectedKey={selectedConnector?.connector_id ?? null}
                  emptyLabel="No connectors registered yet."
                />
              )}
            </AsyncContent>
          </Panel>

          <Panel title="Integration Catalog">
            <AsyncContent state={catalog} emptyLabel="No connector plugins available.">
              {(rows) => (
                <DataConsole
                  columns={catalogColumns}
                  rows={rows}
                  rowKey={(r) => r.connector_id}
                  emptyLabel="No connector plugins available."
                />
              )}
            </AsyncContent>
          </Panel>
        </>
      )}

      {tab === "assets" && (
        <AssetInventoryTab connectors={connectors.data ?? []} catalog={catalog.data ?? []} />
      )}
      {tab === "history" && <DiscoveryHistoryTab connectors={connectors.data ?? []} />}

      {wizardPlugin && (
        <SetupWizard
          plugin={wizardPlugin}
          onClose={() => setWizardPlugin(null)}
          onRegistered={() => {
            setWizardPlugin(null);
            reload();
          }}
        />
      )}

      {selectedConnector && (
        <ConnectorDetailDrawer
          connector={selectedConnector}
          onClose={() => setSelectedConnector(null)}
          onChanged={reload}
        />
      )}
    </>
  );
}

function SetupWizard({
  plugin,
  onClose,
  onRegistered,
}: {
  plugin: ConnectorPlugin;
  onClose: () => void;
  onRegistered: () => void;
}) {
  const [displayName, setDisplayName] = useState(plugin.display_name);
  const [secretValues, setSecretValues] = useState<Record<string, string>>({});
  const [configValues, setConfigValues] = useState<Record<string, string>>(
    Object.fromEntries(plugin.config_fields.map((f) => [f.name, f.default ?? ""]))
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showDocs, setShowDocs] = useState(false);

  async function handleSubmit() {
    setBusy(true);
    setError("");
    try {
      const me = await getMe();
      let backends = await listVaultBackends();
      if (backends.length === 0) {
        const created = await createDefaultVaultBackend();
        backends = [created];
      }
      const backend = backends.find((b) => b.is_default) ?? backends[0];
      const primaryField = plugin.credential_fields[0];
      await registerConnectorWithCredential({
        connector_id: plugin.connector_id,
        display_name: displayName,
        plaintext_secret: secretValues[primaryField.name] ?? "",
        vault_backend_id: backend.backend_id,
        owner_principal_id: me.user_id,
        configuration: configValues,
      });
      onRegistered();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <InvestigationDrawer
      open
      onClose={onClose}
      title={`Configure ${plugin.display_name}`}
      subtitle={`Auth model: ${plugin.auth_model.replace(/_/g, " ")}`}
      fields={[
        { label: "Purpose", value: plugin.docs.purpose },
        {
          label: "Display Name",
          value: (
            <input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-800/80 px-2.5 py-1.5 text-sm text-white focus:border-red-500 focus:outline-none"
            />
          ),
        },
        ...plugin.credential_fields.map((f) => ({
          label: f.label,
          value: (
            <div key={f.name}>
              <input
                type="password"
                autoComplete="off"
                placeholder={f.help_text}
                value={secretValues[f.name] ?? ""}
                onChange={(e) =>
                  setSecretValues((v) => ({ ...v, [f.name]: e.target.value }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-800/80 px-2.5 py-1.5 text-sm text-white focus:border-red-500 focus:outline-none"
              />
              {f.help_text && <p className="mt-1 text-[11px] text-gray-500">{f.help_text}</p>}
              <p className="mt-0.5 text-[10px] text-gray-600">
                Stored encrypted in Credential Vault — never inline.
              </p>
            </div>
          ),
        })),
        ...plugin.config_fields.map((f) => ({
          label: `${f.label}${f.required ? "" : " (optional)"}`,
          value: (
            <div key={f.name}>
              <input
                placeholder={f.help_text}
                value={configValues[f.name] ?? ""}
                onChange={(e) =>
                  setConfigValues((v) => ({ ...v, [f.name]: e.target.value }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-800/80 px-2.5 py-1.5 text-sm text-white focus:border-red-500 focus:outline-none"
              />
              {f.help_text && <p className="mt-1 text-[11px] text-gray-500">{f.help_text}</p>}
            </div>
          ),
        })),
        ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
        {
          label: "Actions",
          value: (
            <div className="flex flex-col gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={handleSubmit}
                className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
              >
                {busy ? "Registering & testing connection…" : "Register Connector"}
              </button>
              <button
                type="button"
                onClick={() => setShowDocs((v) => !v)}
                className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200"
              >
                {showDocs ? "Hide" : "Show"} setup documentation
              </button>
            </div>
          ),
        },
        ...(showDocs
          ? [
              { label: "Required Credentials", value: plugin.docs.required_credentials },
              { label: "Required Permissions", value: plugin.docs.required_permissions },
              { label: "Vendor Configuration", value: plugin.docs.required_vendor_configuration },
              { label: "Validation Process", value: plugin.docs.validation_process },
              { label: "Connectivity Test", value: plugin.docs.connectivity_test },
              { label: "Health Check", value: plugin.docs.health_check },
              { label: "Synchronization", value: plugin.docs.synchronization_strategy },
              { label: "Troubleshooting", value: plugin.docs.troubleshooting_guide },
              { label: "Common Failures", value: plugin.docs.common_failure_scenarios },
              { label: "Recovery Steps", value: plugin.docs.recovery_steps },
              { label: "Firewall / Network", value: plugin.docs.firewall_notes || "None" },
            ]
          : []),
      ]}
    />
  );
}

function ConnectorDetailDrawer({
  connector,
  onClose,
  onChanged,
}: {
  connector: ConnectorRegistration;
  onClose: () => void;
  onChanged: () => void;
}) {
  const health = useAsync(() => getHealthHistory(connector.connector_id), [connector.connector_id]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function handleTest() {
    setBusy(true);
    setError("");
    try {
      await testConnection(connector.connector_id);
      health.reload();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable() {
    if (!window.confirm(`Disable connector "${connector.display_name}"?`)) return;
    setBusy(true);
    setError("");
    try {
      await disableConnector(connector.connector_id);
      onChanged();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Disable failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <InvestigationDrawer
      open
      onClose={onClose}
      title={connector.display_name}
      subtitle={`${connector.connector_type} · ${connector.status}`}
      fields={[
        { label: "Status", value: <StatusPill status={connector.status} /> },
        { label: "Circuit State", value: connector.circuit_state },
        { label: "Credential Type", value: connector.credential_type },
        {
          label: "Recent Health Checks",
          value: (
            <AsyncContent state={health} emptyLabel="No health checks recorded yet.">
              {(rows) => (
                <div className="space-y-1.5">
                  {rows.slice(0, 8).map((h, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <StatusPill status={h.status} />
                      <span className="text-gray-500">{fmtTime(h.checked_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </AsyncContent>
          ),
        },
        ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
        {
          label: "Actions",
          value: (
            <div className="flex gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={handleTest}
                className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
              >
                Test Connection
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={handleDisable}
                className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 disabled:opacity-50"
              >
                Disable
              </button>
            </div>
          ),
        },
      ]}
    />
  );
}

// ── Asset Inventory ──────────────────────────────────────────────────────────

function AssetInventoryTab({
  connectors,
  catalog,
}: {
  connectors: ConnectorRegistration[];
  catalog: ConnectorPlugin[];
}) {
  const [category, setCategory] = useState<string | null>(null);
  const [vendor, setVendor] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const assets = useAsync(
    () => listAssets({ category: category ?? undefined, vendor: vendor ?? undefined }),
    [category, vendor]
  );
  const [selected, setSelected] = useState<DiscoveredAsset | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [runError, setRunError] = useState("");

  const filtered = useMemo(() => {
    const rows = assets.data ?? [];
    if (!search.trim()) return rows;
    const q = search.trim().toLowerCase();
    return rows.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.external_id.toLowerCase().includes(q) ||
        Object.entries(r.tags).some(([k, v]) => `${k}=${v}`.toLowerCase().includes(q))
    );
  }, [assets.data, search]);

  async function handleRunDiscovery(connectorId: string) {
    setRunningId(connectorId);
    setRunError("");
    try {
      await runDiscovery(connectorId, "MANUAL");
      assets.reload();
    } catch (e) {
      setRunError(e instanceof Error ? e.message : "Discovery run failed");
    } finally {
      setRunningId(null);
    }
  }

  const columns: ConsoleColumn<DiscoveredAsset>[] = [
    { key: "name", header: "Asset", width: "20%", render: (r) => (
      <span className="text-gray-200">{r.name}</span>
    ) },
    { key: "vendor", header: "Vendor", width: "12%", render: (r) => r.vendor },
    { key: "category", header: "Category", width: "14%", render: (r) => r.category.replace(/_/g, " ") },
    { key: "health", header: "Health", width: "12%", render: (r) => (
      r.health_status ? <StatusPill status={r.health_status} /> : <span className="text-gray-600">—</span>
    ) },
    { key: "risk", header: "Risk", width: "10%", render: (r) => (
      <EvaluatedRiskScore
        riskScore={r.risk_score}
        securityState={r.security_state}
        complianceState={r.compliance_state}
      />
    ) },
    { key: "tags", header: "Tags", width: "18%", render: (r) => (
      <span className="text-[11px] text-gray-500">
        {Object.entries(r.tags).map(([k, v]) => `${k}=${v}`).join(", ") || "—"}
      </span>
    ) },
    { key: "synced", header: "Last Synced", width: "14%", render: (r) => fmtTime(r.last_synced_at) },
  ];

  const vendors = Array.from(new Set((assets.data ?? []).map((a) => a.vendor)));
  const categories = Array.from(new Set((assets.data ?? []).map((a) => a.category)));

  return (
    <>
      <Panel
        title="Run Discovery"
        className="mb-6"
      >
        {connectors.length === 0 ? (
          <p className="text-xs text-gray-500">No connectors registered — register one on the Connectors tab first.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {connectors.map((c) => {
              const plugin = catalog.find((p) => p.connector_id === c.connector_type);
              // Capability-driven: a connector plugin only offers "Run
              // Discovery" if it actually declares the "discovery"
              // capability (i.e. implements `discover`). Unknown plugins
              // (not present in the catalog response) are treated as
              // capability-unknown and the action is disabled rather than
              // assumed available.
              const canDiscover = plugin ? hasCapability(plugin, "discovery") : false;
              return (
                <button
                  key={c.connector_id}
                  type="button"
                  disabled={runningId === c.connector_id || !canDiscover}
                  title={canDiscover ? undefined : "This connector does not support discovery"}
                  onClick={() => handleRunDiscovery(c.connector_id)}
                  className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 disabled:opacity-50"
                >
                  {runningId === c.connector_id ? "Running…" : `Run Discovery — ${c.display_name}`}
                </button>
              );
            })}
          </div>
        )}
        {runError && <p className="mt-2 text-xs text-red-400">{runError}</p>}
      </Panel>

      <Panel
        title="Discovered Assets"
        right={
          <div className="flex items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder="Search name, id, tags…" />
            <button
              type="button"
              onClick={() => assets.reload()}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
            >
              Refresh
            </button>
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap gap-2">
          <FilterChip label="All Categories" active={category === null} onClick={() => setCategory(null)} />
          {categories.map((c) => (
            <FilterChip key={c} label={c.replace(/_/g, " ")} active={category === c} onClick={() => setCategory(c)} />
          ))}
          <span className="mx-1 text-gray-700">|</span>
          <FilterChip label="All Vendors" active={vendor === null} onClick={() => setVendor(null)} />
          {vendors.map((v) => (
            <FilterChip key={v} label={v} active={vendor === v} onClick={() => setVendor(v)} />
          ))}
        </div>
        <AsyncContent state={assets} emptyLabel="No assets discovered yet. Run discovery on a connector above.">
          {() => (
            <DataConsole
              columns={columns}
              rows={filtered}
              rowKey={(r) => r.asset_id}
              onRowClick={(r) => setSelected(r)}
              selectedKey={selected?.asset_id ?? null}
              emptyLabel="No assets match the current filters."
            />
          )}
        </AsyncContent>
      </Panel>

      {selected && (
        <AssetDetailDrawer asset={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}

function AssetDetailDrawer({ asset, onClose }: { asset: DiscoveredAsset; onClose: () => void }) {
  const relationships = useAsync(() => listAssetRelationships(asset.asset_id), [asset.asset_id]);

  return (
    <InvestigationDrawer
      open
      onClose={onClose}
      title={asset.name}
      subtitle={`${asset.vendor} · ${asset.category.replace(/_/g, " ")}`}
      fields={[
        { label: "External ID", value: <span className="font-mono text-[11px]">{asset.external_id}</span> },
        { label: "Region", value: asset.region ?? "—" },
        { label: "Owner", value: asset.owner ?? "—" },
        { label: "Security State", value: <EvaluationStatePill state={asset.security_state} /> },
        { label: "Compliance State", value: <EvaluationStatePill state={asset.compliance_state} /> },
        { label: "Health", value: asset.health_status ? <StatusPill status={asset.health_status} /> : "—" },
        {
          label: "Risk Score",
          value: (
            <EvaluatedRiskScore
              riskScore={asset.risk_score}
              securityState={asset.security_state}
              complianceState={asset.compliance_state}
            />
          ),
        },
        {
          label: "Tags",
          value:
            Object.keys(asset.tags).length > 0
              ? Object.entries(asset.tags).map(([k, v]) => `${k}=${v}`).join(", ")
              : "—",
        },
        { label: "Discovered At", value: fmtTime(asset.discovered_at) },
        { label: "Last Synced", value: fmtTime(asset.last_synced_at) },
        {
          // Every asset in this list has, by definition, completed at
          // least one discovery sync (that's how it entered the
          // inventory) — `DiscoveredAssetDTO` carries no separate
          // "relationships not yet checked" signal distinct from "checked,
          // found none" (no `evaluated_at`/`relationships_synced_at`
          // field exists on the backend DTO today). An empty list here is
          // therefore always the genuine "no relationships found" case,
          // not an unevaluated one — documented limitation rather than a
          // fabricated distinction.
          label: "Relationships",
          value: (
            <AsyncContent state={relationships} emptyLabel="No relationships found.">
              {(rows) => (
                <div className="space-y-1.5">
                  {rows.length === 0 && <p className="text-xs text-gray-500">No relationships found.</p>}
                  {rows.map((r: AssetRelationship, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-gray-300">{r.relationship_type.replace(/_/g, " ")}</span>
                      <span className="font-mono text-[11px] text-gray-500">
                        → {r.target_external_id}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </AsyncContent>
          ),
        },
      ]}
    />
  );
}

// ── Discovery Timeline / Sync History ────────────────────────────────────────

function DiscoveryHistoryTab({ connectors }: { connectors: ConnectorRegistration[] }) {
  const [connectorId, setConnectorId] = useState<string | null>(
    connectors.length > 0 ? connectors[0].connector_id : null
  );
  const history = useAsync(
    () => (connectorId ? listDiscoveryHistory(connectorId) : Promise.resolve([])),
    [connectorId]
  );

  const columns: ConsoleColumn<SyncRun>[] = [
    { key: "status", header: "Status", width: "14%", render: (r) => <StatusPill status={r.status} /> },
    { key: "mode", header: "Mode", width: "12%", render: (r) => r.mode },
    { key: "started", header: "Started", width: "16%", render: (r) => fmtTime(r.started_at) },
    { key: "completed", header: "Completed", width: "16%", render: (r) => r.completed_at ? fmtTime(r.completed_at) : "—" },
    { key: "discovered", header: "Discovered", width: "10%", render: (r) => r.items_discovered },
    { key: "created", header: "Created", width: "10%", render: (r) => r.items_created },
    { key: "updated", header: "Updated", width: "10%", render: (r) => r.items_updated },
    { key: "error", header: "Error", width: "12%", render: (r) => (
      r.error ? <span className="text-red-400">{r.error}</span> : "—"
    ) },
  ];

  if (connectors.length === 0) {
    return (
      <Panel title="Discovery Timeline">
        <p className="text-xs text-gray-500">No connectors registered yet.</p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Discovery Timeline"
      right={
        <select
          value={connectorId ?? ""}
          onChange={(e) => setConnectorId(e.target.value)}
          className="rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-200"
        >
          {connectors.map((c) => (
            <option key={c.connector_id} value={c.connector_id}>
              {c.display_name}
            </option>
          ))}
        </select>
      }
    >
      <AsyncContent state={history} emptyLabel="No sync runs recorded for this connector yet.">
        {(rows) => (
          <DataConsole
            columns={columns}
            rows={rows}
            rowKey={(r) => r.sync_run_id}
            emptyLabel="No sync runs recorded for this connector yet."
          />
        )}
      </AsyncContent>
    </Panel>
  );
}
