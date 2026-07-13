"use client";

import { useEffect, useState } from "react";
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

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[] | null>(null);
  const [error, setError] = useState("");
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

  function load() {
    listConnectors()
      .then(setConnectors)
      .catch(() => setError("UNAVAILABLE — failed to load connectors."));
  }

  useEffect(load, []);

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
    setSelectedId(connectorId);
    setRuns(null);
    try {
      const r = await listDiscoveryRuns(connectorId);
      setRuns(r);
    } catch {
      setRuns([]);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Connectors</h1>
      <p className="mt-1 text-sm text-gray-400">
        Tenant-owned discovery connectors. Discovery resolves inventory
        identity only — it never executes an attack or grants campaign
        authorization.
      </p>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Register connector</div>
        <div className="mt-2 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Connector name (e.g. 'RedForge Targets')"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <button
            onClick={register}
            disabled={registering || !name}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {registering ? "Registering…" : "Register"}
          </button>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Register directory connector (LDAP)</div>
        <p className="mt-1 text-xs text-gray-500">
          Read-only visibility only — never changes passwords, unlocks accounts,
          or modifies group membership. Credential reference must be configured
          through an approved server-side secret workflow (an environment
          variable name); the bind password itself is never submitted here.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <input
            value={dirName}
            onChange={(e) => setDirName(e.target.value)}
            placeholder="Connector name"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={serverUri}
            onChange={(e) => setServerUri(e.target.value)}
            placeholder="ldaps://ldap.example.com"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={baseDn}
            onChange={(e) => setBaseDn(e.target.value)}
            placeholder="Base DN (dc=example,dc=com)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={bindDn}
            onChange={(e) => setBindDn(e.target.value)}
            placeholder="Bind DN (cn=svc,dc=example,dc=com)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={credentialRef}
            onChange={(e) => setCredentialRef(e.target.value)}
            placeholder="Credential reference (env var name)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
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
          disabled={registeringDirectory || !dirName || !serverUri || !baseDn || !bindDn || !credentialRef}
          className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {registeringDirectory ? "Registering…" : "Register directory connector"}
        </button>
      </div>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Register network connector</div>
        <p className="mt-1 text-xs text-gray-500">
          Bounded, read-only TCP-connect discovery only — never NSE scripts,
          exploits, or arbitrary scanner flags. Default routes (0.0.0.0/0) and
          oversized ranges are rejected at discovery time regardless of what
          is registered here.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <input
            value={netName}
            onChange={(e) => setNetName(e.target.value)}
            placeholder="Connector name"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={netCidr}
            onChange={(e) => setNetCidr(e.target.value)}
            placeholder="CIDR (e.g. 10.0.0.0/28)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={netPorts}
            onChange={(e) => setNetPorts(e.target.value)}
            placeholder="Ports (comma-separated)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
        </div>
        <button
          onClick={registerNetwork}
          disabled={registeringNetwork || !netName || !netCidr}
          className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {registeringNetwork ? "Registering…" : "Register network connector"}
        </button>
      </div>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Register cloud connector (AWS)</div>
        <p className="mt-1 text-xs text-gray-500">
          Read-only AWS discovery only — never modifies resources, policies,
          or IAM. The secret access key is never submitted here; provide a
          credential reference (an environment variable name) configured
          through an approved server-side secret workflow.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <input
            value={cloudName}
            onChange={(e) => setCloudName(e.target.value)}
            placeholder="Connector name"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={cloudRegion}
            onChange={(e) => setCloudRegion(e.target.value)}
            placeholder="Region (e.g. us-east-1)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={cloudAccessKeyId}
            onChange={(e) => setCloudAccessKeyId(e.target.value)}
            placeholder="Access key ID"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={cloudCredentialRef}
            onChange={(e) => setCloudCredentialRef(e.target.value)}
            placeholder="Secret access key credential reference (env var name)"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
        </div>
        <button
          onClick={registerCloud}
          disabled={registeringCloud || !cloudName || !cloudRegion || !cloudAccessKeyId || !cloudCredentialRef}
          className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {registeringCloud ? "Registering…" : "Register cloud connector"}
        </button>
      </div>

      {actionError && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : connectors === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : connectors.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No connectors registered yet.
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {connectors.map((c) => (
            <div key={c.id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-medium text-white">{c.name}</span>
                  <span className="ml-2 text-xs text-gray-600">{c.connector_type}</span>
                </div>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    c.status === "enabled"
                      ? "bg-green-950 text-green-400"
                      : "bg-gray-800 text-gray-500"
                  }`}
                >
                  {c.status}
                </span>
              </div>
              <div className="mt-2 text-xs text-gray-500">
                Last discovery:{" "}
                {c.last_discovery_status ? (
                  <span className="font-mono">{c.last_discovery_status}</span>
                ) : (
                  "never run"
                )}
                {c.last_discovery_completed_at && (
                  <> at {new Date(c.last_discovery_completed_at).toLocaleString()}</>
                )}
              </div>
              <div className="mt-3 flex gap-3 text-xs">
                <button
                  onClick={() => discover(c.id)}
                  disabled={busyId === c.id || c.status !== "enabled"}
                  className="rounded bg-blue-600 px-3 py-1.5 font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  {busyId === c.id ? "Working…" : "Run discovery"}
                </button>
                <button
                  onClick={() => toggle(c)}
                  disabled={busyId === c.id}
                  className="rounded border border-gray-700 px-3 py-1.5 text-gray-400 hover:text-white disabled:opacity-50"
                >
                  {c.status === "enabled" ? "Disable" : "Enable"}
                </button>
                <button
                  onClick={() => openRuns(c.id)}
                  className="rounded border border-gray-700 px-3 py-1.5 text-gray-400 hover:text-white"
                >
                  Discovery runs
                </button>
              </div>

              {selectedId === c.id && (
                <div className="mt-3 border-t border-gray-800 pt-3">
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
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
