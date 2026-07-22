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
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { getMe } from "@/lib/auth";
import {
  createDefaultVaultBackend,
  disableConnector,
  getHealthHistory,
  listCatalog,
  listConnectors,
  listVaultBackends,
  registerConnectorWithCredential,
  testConnection,
  type ConnectorPlugin,
  type ConnectorRegistration,
} from "@/lib/integrations";

export default function IntegrationsPage() {
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
