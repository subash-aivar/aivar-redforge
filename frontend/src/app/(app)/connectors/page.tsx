"use client";

import { useState } from "react";
import {
  disableConnector,
  enableConnector,
  listConnectors,
  listDiscoveryRuns,
  registerConnector,
  startDiscovery,
  type Connector,
  type DiscoveryRun,
} from "@/lib/assets";
import { registerDirectoryConnector } from "@/lib/directorySecurity";
import { registerNetworkConnector } from "@/lib/networkExposure";
import { registerCloudConnector } from "@/lib/cloudSecurity";
import {
  AsyncContent,
  DataConsole,
  FormField,
  KpiTile,
  Panel,
  PageHeader,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";

export default function ConnectorsPage() {
  const connectorsState = useAsync(() => listConnectors(), []);
  const [actionError, setActionError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [registering, setRegistering] = useState(false);

  const [dirName, setDirName] = useState("");
  const [serverUri, setServerUri] = useState("");
  const [baseDn, setBaseDn] = useState("");
  const [bindDn, setBindDn] = useState("");
  const [credentialRef, setCredentialRef] = useState("");
  const [useStartTls, setUseStartTls] = useState(false);
  const [registeringDirectory, setRegisteringDirectory] = useState(false);

  const [netName, setNetName] = useState("");
  const [netCidr, setNetCidr] = useState("");
  const [netPorts, setNetPorts] = useState("22,80,443");
  const [registeringNetwork, setRegisteringNetwork] = useState(false);

  const [cloudName, setCloudName] = useState("");
  const [cloudRegion, setCloudRegion] = useState("us-east-1");
  const [cloudAccessKeyId, setCloudAccessKeyId] = useState("");
  const [cloudCredentialRef, setCloudCredentialRef] = useState("");
  const [registeringCloud, setRegisteringCloud] = useState(false);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [runs, setRuns] = useState<DiscoveryRun[] | null>(null);
  const [showRegisterForms, setShowRegisterForms] = useState(false);

  function load() {
    connectorsState.reload();
  }

  async function register() {
    setRegistering(true);
    setActionError("");
    try {
      await registerConnector(name, "");
      setName("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Registration failed";
      setActionError(msg);
    } finally {
      setRegistering(false);
    }
  }

  async function registerDirectory() {
    setRegisteringDirectory(true);
    setActionError("");
    try {
      await registerDirectoryConnector({
        name: dirName,
        server_uri: serverUri,
        base_dn: baseDn,
        bind_dn: bindDn,
        credential_reference_id: credentialRef,
        use_start_tls: useStartTls,
        allow_insecure_plaintext: false,
        privileged_group_dns: [],
      });
      setDirName("");
      setServerUri("");
      setBaseDn("");
      setBindDn("");
      setCredentialRef("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Directory connector registration failed";
      setActionError(msg);
    } finally {
      setRegisteringDirectory(false);
    }
  }

  async function registerNetwork() {
    setRegisteringNetwork(true);
    setActionError("");
    try {
      const ports = netPorts
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !Number.isNaN(p));
      await registerNetworkConnector({ name: netName, network_cidr: netCidr, ports });
      setNetName("");
      setNetCidr("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network connector registration failed";
      setActionError(msg);
    } finally {
      setRegisteringNetwork(false);
    }
  }

  async function registerCloud() {
    setRegisteringCloud(true);
    setActionError("");
    try {
      await registerCloudConnector({
        name: cloudName,
        region: cloudRegion,
        access_key_id: cloudAccessKeyId,
        secret_access_key_credential_reference_id: cloudCredentialRef,
      });
      setCloudName("");
      setCloudAccessKeyId("");
      setCloudCredentialRef("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Cloud connector registration failed";
      setActionError(msg);
    } finally {
      setRegisteringCloud(false);
    }
  }

  async function toggle(c: Connector) {
    setBusyId(c.id);
    setActionError("");
    try {
      if (c.status === "enabled") {
        await disableConnector(c.id);
      } else {
        await enableConnector(c.id);
      }
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Action failed";
      setActionError(msg);
    } finally {
      setBusyId(null);
    }
  }

  async function discover(connectorId: string) {
    setBusyId(connectorId);
    setActionError("");
    try {
      await startDiscovery(connectorId);
      load();
      if (selectedId === connectorId) await openRuns(connectorId);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Discovery failed to start";
      setActionError(msg);
    } finally {
      setBusyId(null);
    }
  }

  async function openRuns(connectorId: string) {
    setSelectedId(connectorId === selectedId ? null : connectorId);
    setRuns(null);
    if (connectorId === selectedId) return;
    try {
      const r = await listDiscoveryRuns(connectorId);
      setRuns(r);
    } catch {
      setRuns([]);
    }
  }

  const connectors = connectorsState.data ?? [];
  const total = connectors.length;
  const enabledCount = connectors.filter((c) => c.status === "enabled").length;
  const disabledCount = connectors.filter((c) => c.status !== "enabled").length;
  const errorCount = connectors.filter((c) => c.last_discovery_status === "failed").length;
  const typeCounts = connectors.reduce<Record<string, number>>((acc, c) => {
    acc[c.connector_type] = (acc[c.connector_type] ?? 0) + 1;
    return acc;
  }, {});

  const columns: ConsoleColumn<Connector>[] = [
    {
      key: "name",
      header: "Name",
      render: (c) => (
        <div>
          <span className="font-medium text-gray-100">{c.name}</span>
          <span className="ml-2 text-[10px] text-gray-600">{c.connector_type}</span>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (c) => <StatusPill status={c.status === "enabled" ? "active" : "not_configured"} />,
    },
    {
      key: "last_discovery",
      header: "Last discovery",
      render: (c) => (
        <span className="text-xs">
          {c.last_discovery_status ? (
            <span
              className={
                c.last_discovery_status === "failed"
                  ? "font-mono text-red-400"
                  : "font-mono text-gray-300"
              }
            >
              {c.last_discovery_status}
            </span>
          ) : (
            <span className="text-gray-600">never run</span>
          )}
          {c.last_discovery_completed_at && (
            <span className="ml-1 text-gray-600">
              at {new Date(c.last_discovery_completed_at).toLocaleString()}
            </span>
          )}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      render: (c) => (
        <div className="flex gap-2 text-xs" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={() => discover(c.id)}
            disabled={busyId === c.id || c.status !== "enabled"}
            className="rounded bg-blue-600 px-2 py-1 font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {busyId === c.id ? "Working…" : "Run discovery"}
          </button>
          <button
            onClick={() => toggle(c)}
            disabled={busyId === c.id}
            className="rounded border border-gray-700 px-2 py-1 text-gray-400 hover:text-white disabled:opacity-50"
          >
            {c.status === "enabled" ? "Disable" : "Enable"}
          </button>
          <button
            onClick={() => openRuns(c.id)}
            className="rounded border border-gray-700 px-2 py-1 text-gray-400 hover:text-white"
          >
            {selectedId === c.id ? "Hide runs" : "Discovery runs"}
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Connectors"
        subtitle="Tenant-owned discovery connectors. Discovery resolves inventory identity only — it never executes an attack or grants campaign authorization."
        actions={
          <button
            onClick={() => setShowRegisterForms((v) => !v)}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:text-white"
          >
            {showRegisterForms ? "Hide register forms" : "Register connector"}
          </button>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <KpiTile label="Total connectors" value={total} />
        <KpiTile label="Enabled" value={enabledCount} tone={enabledCount > 0 ? "ok" : "default"} />
        <KpiTile
          label="Disabled"
          value={disabledCount}
          tone={disabledCount > 0 ? "warning" : "default"}
        />
        <KpiTile
          label="Last discovery failed"
          value={errorCount}
          tone={errorCount > 0 ? "danger" : "default"}
        />
        <KpiTile
          label="By type"
          value={
            Object.keys(typeCounts).length === 0
              ? "—"
              : Object.entries(typeCounts)
                  .map(([t, n]) => `${t}: ${n}`)
                  .join(", ")
          }
        />
      </div>

      {actionError && (
        <div role="alert" className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      <Panel title="Registered connectors" className="mt-6">
        <AsyncContent
          state={connectorsState}
          empty={(data) => data.length === 0}
          emptyLabel="No connectors registered yet."
        >
          {(data) => (
            <>
              <DataConsole
                columns={columns}
                rows={data}
                rowKey={(c) => c.id}
                onRowClick={(c) => openRuns(c.id)}
                selectedKey={selectedId}
                emptyLabel="No connectors registered yet."
              />
              {selectedId && (
                <div className="mt-4 border-t border-gray-800 pt-4">
                  <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                    Discovery runs
                  </div>
                  {runs === null ? (
                    <div className="text-xs text-gray-500">Loading runs…</div>
                  ) : runs.length === 0 ? (
                    <div className="text-xs text-gray-600">No discovery runs yet.</div>
                  ) : (
                    <div className="space-y-2">
                      {runs.map((r) => (
                        <div
                          key={r.job_id}
                          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span
                              className={`font-mono font-medium ${
                                r.status === "completed"
                                  ? "text-green-400"
                                  : r.status === "failed"
                                    ? "text-red-400"
                                    : r.status === "running"
                                      ? "text-blue-400"
                                      : "text-gray-500"
                              }`}
                            >
                              {r.status.toUpperCase()}
                            </span>
                            <span className="text-gray-600">
                              {new Date(r.started_at).toLocaleString()}
                            </span>
                          </div>
                          <div className="mt-1 flex gap-3 text-gray-500">
                            <span>discovered: {r.assets_discovered}</span>
                            <span>normalized: {r.assets_normalized}</span>
                            <span>failed: {r.assets_failed}</span>
                          </div>
                          {r.error_message && (
                            <div className="mt-1 text-red-400">{r.error_message}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </AsyncContent>
      </Panel>

      {showRegisterForms && (
        <div className="mt-6 space-y-4">
          <Panel title="Register generic connector">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <FormField label="Connector name" required>
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. RedForge Targets"
                    className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                  />
                </FormField>
              </div>
              <button
                onClick={register}
                disabled={registering || !name}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
              >
                {registering ? "Registering…" : "Register"}
              </button>
            </div>
          </Panel>

          <Panel title="Register directory connector (LDAP)">
            <p className="text-xs text-gray-500">
              Read-only visibility only — never changes passwords, unlocks accounts,
              or modifies group membership. Credential reference must be configured
              through an approved server-side secret workflow (an environment
              variable name); the bind password itself is never submitted here.
            </p>
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              <FormField label="Connector name" required>
                <input
                  value={dirName}
                  onChange={(e) => setDirName(e.target.value)}
                  placeholder="e.g. Corp LDAP"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Server URI" required>
                <input
                  value={serverUri}
                  onChange={(e) => setServerUri(e.target.value)}
                  placeholder="ldaps://ldap.example.com"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Base DN" required>
                <input
                  value={baseDn}
                  onChange={(e) => setBaseDn(e.target.value)}
                  placeholder="dc=example,dc=com"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Bind DN" required>
                <input
                  value={bindDn}
                  onChange={(e) => setBindDn(e.target.value)}
                  placeholder="cn=svc,dc=example,dc=com"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField
                label="Credential reference"
                required
                hint="Environment variable name — the bind password itself is never submitted here."
              >
                <input
                  value={credentialRef}
                  onChange={(e) => setCredentialRef(e.target.value)}
                  placeholder="e.g. LDAP_BIND_PASSWORD"
                  autoComplete="off"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <label className="flex items-center gap-2 text-sm text-gray-400">
                <input
                  type="checkbox"
                  checked={useStartTls}
                  onChange={(e) => setUseStartTls(e.target.checked)}
                />
                Use StartTLS
              </label>
            </div>
            <button
              onClick={registerDirectory}
              disabled={
                registeringDirectory || !dirName || !serverUri || !baseDn || !bindDn || !credentialRef
              }
              className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {registeringDirectory ? "Registering…" : "Register directory connector"}
            </button>
          </Panel>

          <Panel title="Register network connector">
            <p className="text-xs text-gray-500">
              Bounded, read-only TCP-connect discovery only — never NSE scripts,
              exploits, or arbitrary scanner flags. Default routes (0.0.0.0/0) and
              oversized ranges are rejected at discovery time regardless of what
              is registered here.
            </p>
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
              <FormField label="Connector name" required>
                <input
                  value={netName}
                  onChange={(e) => setNetName(e.target.value)}
                  placeholder="e.g. Corp Network"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="CIDR" required>
                <input
                  value={netCidr}
                  onChange={(e) => setNetCidr(e.target.value)}
                  placeholder="10.0.0.0/28"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Ports" hint="Comma-separated.">
                <input
                  value={netPorts}
                  onChange={(e) => setNetPorts(e.target.value)}
                  placeholder="22,80,443"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
            </div>
            <button
              onClick={registerNetwork}
              disabled={registeringNetwork || !netName || !netCidr}
              className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {registeringNetwork ? "Registering…" : "Register network connector"}
            </button>
          </Panel>

          <Panel title="Register cloud connector (AWS)">
            <p className="text-xs text-gray-500">
              Read-only AWS discovery only — never modifies resources, policies,
              or IAM. The secret access key is never submitted here; provide a
              credential reference (an environment variable name) configured
              through an approved server-side secret workflow.
            </p>
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              <FormField label="Connector name" required>
                <input
                  value={cloudName}
                  onChange={(e) => setCloudName(e.target.value)}
                  placeholder="e.g. Prod AWS Account"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Region" required>
                <input
                  value={cloudRegion}
                  onChange={(e) => setCloudRegion(e.target.value)}
                  placeholder="us-east-1"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField label="Access key ID" required>
                <input
                  value={cloudAccessKeyId}
                  onChange={(e) => setCloudAccessKeyId(e.target.value)}
                  placeholder="AKIA…"
                  autoComplete="off"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
              <FormField
                label="Secret access key credential reference"
                required
                hint="Environment variable name — the secret access key itself is never submitted here."
              >
                <input
                  value={cloudCredentialRef}
                  onChange={(e) => setCloudCredentialRef(e.target.value)}
                  placeholder="e.g. AWS_SECRET_ACCESS_KEY"
                  autoComplete="off"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
                />
              </FormField>
            </div>
            <button
              onClick={registerCloud}
              disabled={
                registeringCloud || !cloudName || !cloudRegion || !cloudAccessKeyId || !cloudCredentialRef
              }
              className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {registeringCloud ? "Registering…" : "Register cloud connector"}
            </button>
          </Panel>
        </div>
      )}
    </div>
  );
}
