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
  listCredentials,
  getCredential,
  resolveCredential,
  disableCredential,
  enableCredential,
  revokeCredential,
  emergencyRevokeCredential,
  rotateCredential,
  commitRotation,
  abortRotation,
  listVersions,
  listAuditEntries,
  listRotationPolicies,
  createRotationPolicy,
  deleteRotationPolicy,
  listExpirationPolicies,
  createExpirationPolicy,
  deleteExpirationPolicy,
  listVaultBackends,
  registerVaultBackend,
  deleteVaultBackend,
  createCredential,
  type CredentialResponse,
  type VersionResponse,
  type RotationPolicyResponse,
  type ExpirationPolicyResponse,
  type VaultBackendResponse,
} from "@/lib/credentialVault";

export default function CredentialVaultPage() {
  const [tab, setTab] = useState<"credentials" | "policies" | "backends">("credentials");

  return (
    <>
      <PageHeader
        title="Credential Vault"
        subtitle="Secret lifecycle management: credentials, rotation/expiration policies, vault backends, and audit trail"
      />

      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["credentials", "policies", "backends"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t === "credentials" ? "Credentials" : t === "policies" ? "Policies" : "Vault Backends"}
          </button>
        ))}
      </div>

      {tab === "credentials" && <CredentialsTab />}
      {tab === "policies" && <PoliciesTab />}
      {tab === "backends" && <BackendsTab />}
    </>
  );
}

// ─── Credentials Tab ──────────────────────────────────────────────────────────

function CredentialsTab() {
  const credentials = useAsync(() => listCredentials({ limit: 200 }), []);
  const [selected, setSelected] = useState<CredentialResponse | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const backends = useAsync(() => listVaultBackends(), []);

  const cols: ConsoleColumn<CredentialResponse>[] = [
    { key: "name", header: "Name", width: "20%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "category", header: "Category", width: "14%", render: (r) => r.category },
    { key: "subtype", header: "Subtype", width: "14%", render: (r) => r.subtype },
    { key: "state", header: "State", width: "14%", render: (r) => <StatusPill status={r.state} /> },
    { key: "updated", header: "Updated", width: "18%", render: (r) => fmtTime(r.updated_at) },
    { key: "id", header: "ID", width: "20%", render: (r) => <span className="font-mono text-[10px] text-gray-600">{r.credential_id.slice(0, 12)}…</span> },
  ];

  return (
    <AsyncContent state={credentials}>
      {(data) => (
        <>
          <div className="mb-6 flex items-center justify-between">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total Credentials" value={data.total} />
              <KpiTile label="Active" value={data.items.filter((c) => c.state === "ACTIVE").length} tone="ok" />
              <KpiTile label="Disabled" value={data.items.filter((c) => c.state === "DISABLED").length} tone="warning" />
              <KpiTile label="Revoked" value={data.items.filter((c) => c.state === "REVOKED").length} tone="danger" />
            </div>
            <button
              onClick={() => setShowCreate(true)}
              className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
            >
              New Credential
            </button>
          </div>
          <DataConsole columns={cols} rows={data.items} rowKey={(r) => r.credential_id} onRowClick={setSelected} emptyLabel="No credentials stored in the vault." />

          {selected && (
            <CredentialDetailDrawer
              credentialId={selected.credential_id}
              onClose={() => setSelected(null)}
              onChanged={() => credentials.reload()}
            />
          )}

          {showCreate && (
            <CreateCredentialModal
              backends={backends.data || []}
              onClose={() => setShowCreate(false)}
              onCreated={() => {
                credentials.reload();
                setShowCreate(false);
              }}
            />
          )}
        </>
      )}
    </AsyncContent>
  );
}

function CredentialDetailDrawer({
  credentialId,
  onClose,
  onChanged,
}: {
  credentialId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const detail = useAsync(() => getCredential(credentialId), [credentialId]);
  const versions = useAsync(() => listVersions(credentialId), [credentialId]);
  const audit = useAsync(() => listAuditEntries(credentialId, { limit: 50 }), [credentialId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [resolvedSecret, setResolvedSecret] = useState<string | null>(null);
  const [purpose, setPurpose] = useState("");
  const [breakGlass, setBreakGlass] = useState(false);
  const [justification, setJustification] = useState("");
  const [reason, setReason] = useState("");
  const [newSecret, setNewSecret] = useState("");

  async function run<T>(fn: () => Promise<T>, successMessage: string) {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(successMessage);
      detail.reload();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleResolve() {
    if (!purpose.trim()) {
      setError("Purpose is required to resolve a credential.");
      return;
    }
    if (breakGlass && !justification.trim()) {
      setError("Break-glass access requires a justification.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await resolveCredential(credentialId, {
        purpose,
        break_glass: breakGlass,
        justification: breakGlass ? justification : undefined,
      });
      const decoded = atob(r.secret_b64);
      setResolvedSecret(decoded);
      audit.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Resolve failed");
    } finally {
      setBusy(false);
    }
  }

  if (detail.loading || !detail.data) {
    return (
      <InvestigationDrawer
        open
        title="Credential Detail"
        onClose={onClose}
        fields={[{ label: "Loading", value: detail.forbidden ? "You don't have permission to view this credential." : "Loading…" }]}
      />
    );
  }

  const c = detail.data;
  const fields: DrawerField[] = [
    { label: "State", value: <StatusPill status={c.state} /> },
    { label: "Category / Subtype", value: `${c.category} / ${c.subtype}` },
    { label: "Description", value: c.description || "—" },
    { label: "Version", value: c.version },
    { label: "Created / Updated", value: `${fmtTime(c.created_at)} — ${fmtTime(c.updated_at)}` },
    {
      label: "Resolve Secret",
      value: (
        <div className="space-y-2">
          <FormField label="Purpose" required hint="Audit-logged with every resolve.">
            <input
              id="resolve-purpose"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="e.g. rotating provider key"
              className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
            />
          </FormField>
          <label className="flex items-center gap-2 text-xs text-gray-400">
            <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
            Break-glass access
          </label>
          {breakGlass && (
            <FormField label="Break-glass justification" required>
              <input
                id="resolve-justification"
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                placeholder="Required for break-glass — reviewed in audit"
                className="w-full rounded-md border border-amber-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
              />
            </FormField>
          )}
          <button
            onClick={handleResolve}
            disabled={busy}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
          >
            Resolve Secret
          </button>
          {resolvedSecret !== null && (
            <div className="rounded-md border border-amber-800 bg-amber-950/30 p-2">
              <p className="mb-1 text-[10px] uppercase tracking-wide text-amber-400">
                Secret revealed — audit-logged. Clear when done.
              </p>
              <div className="flex items-center justify-between gap-2">
                <code className="break-all text-xs text-gray-200">{resolvedSecret}</code>
                <button
                  onClick={() => setResolvedSecret(null)}
                  className="shrink-0 rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400"
                >
                  Clear
                </button>
              </div>
            </div>
          )}
        </div>
      ),
    },
    {
      label: "Lifecycle Actions",
      value: (
        <div className="space-y-2">
          <FormField label="Reason" hint="Justification for disable, revoke, or emergency revoke.">
            <input
              id="lifecycle-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. key leaked in logs"
              className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
            />
          </FormField>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => run(() => disableCredential(credentialId, reason || "disabled via console"), "Credential disabled.")}
              disabled={busy || c.state === "DISABLED"}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
            >
              Disable
            </button>
            <button
              onClick={() => run(() => enableCredential(credentialId), "Credential enabled.")}
              disabled={busy || c.state === "ACTIVE"}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
            >
              Enable
            </button>
            <button
              onClick={() => run(() => revokeCredential(credentialId, reason || "revoked via console"), "Credential revoked.")}
              disabled={busy || c.state === "REVOKED"}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
            >
              Revoke
            </button>
            <button
              onClick={() => run(() => emergencyRevokeCredential(credentialId, reason || "emergency revoke via console"), "Credential emergency-revoked.")}
              disabled={busy}
              className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-40"
            >
              Emergency Revoke
            </button>
          </div>
        </div>
      ),
    },
    {
      label: "Rotation",
      value: (
        <div className="space-y-2">
          <FormField label="New secret value" required>
            <input
              id="rotate-new-secret"
              type="password"
              autoComplete="new-password"
              value={newSecret}
              onChange={(e) => setNewSecret(e.target.value)}
              placeholder="Enter the replacement secret"
              className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200"
            />
          </FormField>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => {
                if (!newSecret.trim()) {
                  setError("New secret value is required to rotate.");
                  return;
                }
                run(() => rotateCredential(credentialId, { new_plaintext_secret: newSecret }), "Rotation started.");
                setNewSecret("");
              }}
              disabled={busy}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
            >
              Rotate
            </button>
            <button
              onClick={() => run(() => commitRotation(credentialId), "Rotation committed.")}
              disabled={busy}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
            >
              Commit Rotation
            </button>
            <button
              onClick={() => run(() => abortRotation(credentialId), "Rotation aborted.")}
              disabled={busy}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
            >
              Abort Rotation
            </button>
          </div>
        </div>
      ),
    },
    {
      label: "Version History",
      value: (
        <AsyncContent state={versions} empty={(d) => d.items.length === 0} emptyLabel="No versions recorded.">
          {(v) => (
            <div className="max-h-40 divide-y divide-gray-800 overflow-y-auto">
              {v.items.map((ver: VersionResponse) => (
                <div key={ver.version_id} className="flex items-center justify-between py-1.5 text-xs">
                  <span className="text-gray-300">v{ver.version_number}</span>
                  <StatusPill status={ver.version_state} />
                  <span className="text-gray-500">{fmtTime(ver.created_at)}</span>
                </div>
              ))}
            </div>
          )}
        </AsyncContent>
      ),
    },
    {
      label: "Audit Trail",
      value: (
        <AsyncContent state={audit} empty={(d) => d.items.length === 0} emptyLabel="No audit entries recorded.">
          {(a) => (
            <div className="max-h-48 divide-y divide-gray-800 overflow-y-auto">
              {a.items.map((entry) => (
                <div key={entry.entry_id} className="py-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300">{entry.operation}</span>
                    <span className={entry.outcome === "SUCCESS" ? "text-emerald-400" : "text-red-400"}>{entry.outcome}</span>
                  </div>
                  <div className="text-[10px] text-gray-600">{fmtTime(entry.occurred_at)} — {entry.detail}</div>
                </div>
              ))}
            </div>
          )}
        </AsyncContent>
      ),
    },
    ...(error ? [{ label: "Error", value: <span className="text-red-400">{error}</span> }] : []),
    ...(message ? [{ label: "Result", value: <span className="text-emerald-400">{message}</span> }] : []),
  ];

  return (
    <InvestigationDrawer
      open
      title={c.name}
      subtitle={c.credential_id}
      onClose={onClose}
      fields={fields}
    />
  );
}

function CreateCredentialModal({
  backends,
  onClose,
  onCreated,
}: {
  backends: VaultBackendResponse[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [category, setCategory] = useState("");
  const [subtype, setSubtype] = useState("");
  const [vaultBackendId, setVaultBackendId] = useState(backends[0]?.backend_id || "");
  const [secret, setSecret] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!name.trim() || !category.trim() || !subtype.trim() || !vaultBackendId || !secret.trim()) {
      setError("Name, category, subtype, vault backend, and secret value are required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await createCredential({
        name,
        category,
        subtype,
        vault_backend_id: vaultBackendId,
        plaintext_secret: secret,
        description: description || undefined,
      });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create credential");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="New Credential" onClose={onClose}>
      <div className="space-y-2">
        <FormField label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Prod OpenAI API key"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Category" required>
          <input
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            placeholder="e.g. API_KEY"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Subtype" required>
          <input
            value={subtype}
            onChange={(e) => setSubtype(e.target.value)}
            placeholder="e.g. openai"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        {backends.length > 0 ? (
          <FormField label="Vault backend" required>
            <select
              value={vaultBackendId}
              onChange={(e) => setVaultBackendId(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
            >
              {backends.map((b) => (
                <option key={b.backend_id} value={b.backend_id}>
                  {b.name}
                </option>
              ))}
            </select>
          </FormField>
        ) : (
          <p className="text-xs text-amber-400">No vault backends registered. Register one first.</p>
        )}
        <FormField label="Secret value" required>
          <input
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="Enter the plaintext secret"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
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
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">Cancel</button>
        <button disabled={busy} onClick={submit} className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50">
          {busy ? "Creating…" : "Create"}
        </button>
      </div>
    </FormModal>
  );
}

// ─── Policies Tab ─────────────────────────────────────────────────────────────

function PoliciesTab() {
  const rotationPolicies = useAsync(() => listRotationPolicies(), []);
  const expirationPolicies = useAsync(() => listExpirationPolicies(), []);
  const [showCreateRotation, setShowCreateRotation] = useState(false);
  const [showCreateExpiration, setShowCreateExpiration] = useState(false);
  const [selectedRotation, setSelectedRotation] = useState<RotationPolicyResponse | null>(null);
  const [selectedExpiration, setSelectedExpiration] = useState<ExpirationPolicyResponse | null>(null);

  const rotationCols: ConsoleColumn<RotationPolicyResponse>[] = [
    { key: "name", header: "Name", width: "22%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "interval", header: "Interval (days)", width: "16%", render: (r) => r.interval_days ?? "—" },
    { key: "max_versions", header: "Max Versions", width: "14%", render: (r) => r.max_versions_kept },
    { key: "auto", header: "Auto Rotate / Commit", width: "20%", render: (r) => `${r.auto_rotate ? "Yes" : "No"} / ${r.auto_commit ? "Yes" : "No"}` },
    {
      key: "actions",
      header: "Actions",
      width: "28%",
      render: (r) => (
        <button
          onClick={async (e) => {
            e.stopPropagation();
            if (confirm(`Delete rotation policy "${r.name}"?`)) {
              await deleteRotationPolicy(r.policy_id);
              rotationPolicies.reload();
            }
          }}
          className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300"
        >
          Delete
        </button>
      ),
    },
  ];

  const expirationCols: ConsoleColumn<ExpirationPolicyResponse>[] = [
    { key: "name", header: "Name", width: "26%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "ttl", header: "TTL (days)", width: "16%", render: (r) => r.ttl_days },
    { key: "warn", header: "Warn (days before)", width: "18%", render: (r) => r.warn_days_before },
    { key: "hard", header: "Hard Expire", width: "14%", render: (r) => (r.hard_expire ? "Yes" : "No") },
    {
      key: "actions",
      header: "Actions",
      width: "26%",
      render: (r) => (
        <button
          onClick={async (e) => {
            e.stopPropagation();
            if (confirm(`Delete expiration policy "${r.name}"?`)) {
              await deleteExpirationPolicy(r.policy_id);
              expirationPolicies.reload();
            }
          }}
          className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile
          label="Rotation Policies"
          value={rotationPolicies.data ? rotationPolicies.data.length : "—"}
        />
        <KpiTile
          label="Auto-Rotate Enabled"
          value={rotationPolicies.data ? rotationPolicies.data.filter((p) => p.auto_rotate).length : "—"}
          tone="ok"
        />
        <KpiTile
          label="Expiration Policies"
          value={expirationPolicies.data ? expirationPolicies.data.length : "—"}
        />
        <KpiTile
          label="Hard-Expire Enabled"
          value={expirationPolicies.data ? expirationPolicies.data.filter((p) => p.hard_expire).length : "—"}
          tone="warning"
        />
      </div>

      <Panel
        title="Rotation Policies"
        right={
          <button onClick={() => setShowCreateRotation(true)} className="rounded-md border border-gray-700 px-2.5 py-1 text-[11px] text-gray-300 hover:border-red-800 hover:text-red-300">
            + New Rotation Policy
          </button>
        }
      >
        <AsyncContent state={rotationPolicies} empty={(d) => d.length === 0} emptyLabel="No rotation policies configured.">
          {(list) => (
            <DataConsole
              columns={rotationCols}
              rows={list}
              rowKey={(r) => r.policy_id}
              onRowClick={setSelectedRotation}
              selectedKey={selectedRotation?.policy_id}
              emptyLabel="No rotation policies configured."
            />
          )}
        </AsyncContent>
      </Panel>

      <Panel
        title="Expiration Policies"
        right={
          <button onClick={() => setShowCreateExpiration(true)} className="rounded-md border border-gray-700 px-2.5 py-1 text-[11px] text-gray-300 hover:border-red-800 hover:text-red-300">
            + New Expiration Policy
          </button>
        }
      >
        <AsyncContent state={expirationPolicies} empty={(d) => d.length === 0} emptyLabel="No expiration policies configured.">
          {(list) => (
            <DataConsole
              columns={expirationCols}
              rows={list}
              rowKey={(r) => r.policy_id}
              onRowClick={setSelectedExpiration}
              selectedKey={selectedExpiration?.policy_id}
              emptyLabel="No expiration policies configured."
            />
          )}
        </AsyncContent>
      </Panel>

      {showCreateRotation && (
        <CreateRotationPolicyModal
          onClose={() => setShowCreateRotation(false)}
          onCreated={() => {
            rotationPolicies.reload();
            setShowCreateRotation(false);
          }}
        />
      )}
      {showCreateExpiration && (
        <CreateExpirationPolicyModal
          onClose={() => setShowCreateExpiration(false)}
          onCreated={() => {
            expirationPolicies.reload();
            setShowCreateExpiration(false);
          }}
        />
      )}

      {selectedRotation && (
        <InvestigationDrawer
          open
          title={selectedRotation.name}
          subtitle="Rotation Policy"
          entityId={selectedRotation.policy_id}
          onClose={() => setSelectedRotation(null)}
          fields={[
            { label: "Interval (days)", value: selectedRotation.interval_days ?? "—" },
            { label: "Max Versions Kept", value: selectedRotation.max_versions_kept },
            { label: "Notify Days Before", value: selectedRotation.notify_days_before },
            { label: "Auto Rotate", value: selectedRotation.auto_rotate ? "Yes" : "No" },
            { label: "Auto Commit", value: selectedRotation.auto_commit ? "Yes" : "No" },
            { label: "Commit Window (hours)", value: selectedRotation.commit_window_hours },
            { label: "Created / Updated", value: `${fmtTime(selectedRotation.created_at)} — ${fmtTime(selectedRotation.updated_at)}` },
            {
              label: "Actions",
              value: (
                <button
                  onClick={async () => {
                    if (confirm(`Delete rotation policy "${selectedRotation.name}"?`)) {
                      await deleteRotationPolicy(selectedRotation.policy_id);
                      setSelectedRotation(null);
                      rotationPolicies.reload();
                    }
                  }}
                  className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
                >
                  Delete Policy
                </button>
              ),
            },
          ]}
        />
      )}

      {selectedExpiration && (
        <InvestigationDrawer
          open
          title={selectedExpiration.name}
          subtitle="Expiration Policy"
          entityId={selectedExpiration.policy_id}
          onClose={() => setSelectedExpiration(null)}
          fields={[
            { label: "TTL (days)", value: selectedExpiration.ttl_days },
            { label: "Warn Days Before", value: selectedExpiration.warn_days_before },
            { label: "Hard Expire", value: selectedExpiration.hard_expire ? "Yes" : "No" },
            { label: "Created / Updated", value: `${fmtTime(selectedExpiration.created_at)} — ${fmtTime(selectedExpiration.updated_at)}` },
            {
              label: "Actions",
              value: (
                <button
                  onClick={async () => {
                    if (confirm(`Delete expiration policy "${selectedExpiration.name}"?`)) {
                      await deleteExpirationPolicy(selectedExpiration.policy_id);
                      setSelectedExpiration(null);
                      expirationPolicies.reload();
                    }
                  }}
                  className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
                >
                  Delete Policy
                </button>
              ),
            },
          ]}
        />
      )}
    </div>
  );
}

function CreateRotationPolicyModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [intervalDays, setIntervalDays] = useState(90);
  const [maxVersions, setMaxVersions] = useState(5);
  const [notifyDays, setNotifyDays] = useState(7);
  const [autoRotate, setAutoRotate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await createRotationPolicy({
        name,
        interval_days: intervalDays,
        max_versions_kept: maxVersions,
        notify_days_before: notifyDays,
        auto_rotate: autoRotate,
      });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create policy");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="New Rotation Policy" onClose={onClose}>
      <div className="space-y-2">
        <FormField label="Policy name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. 90-day API key rotation"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Interval (days)">
          <input
            type="number"
            value={intervalDays}
            onChange={(e) => setIntervalDays(Number(e.target.value))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Max versions kept">
          <input
            type="number"
            value={maxVersions}
            onChange={(e) => setMaxVersions(Number(e.target.value))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Notify days before">
          <input
            type="number"
            value={notifyDays}
            onChange={(e) => setNotifyDays(Number(e.target.value))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input type="checkbox" checked={autoRotate} onChange={(e) => setAutoRotate(e.target.checked)} />
          Auto-rotate
        </label>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-xs text-red-400">
          {error}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">Cancel</button>
        <button disabled={busy} onClick={submit} className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50">
          {busy ? "Creating…" : "Create"}
        </button>
      </div>
    </FormModal>
  );
}

function CreateExpirationPolicyModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [ttlDays, setTtlDays] = useState(365);
  const [warnDays, setWarnDays] = useState(30);
  const [hardExpire, setHardExpire] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await createExpirationPolicy({ name, ttl_days: ttlDays, warn_days_before: warnDays, hard_expire: hardExpire });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create policy");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="New Expiration Policy" onClose={onClose}>
      <div className="space-y-2">
        <FormField label="Policy name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. 1-year credential TTL"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="TTL (days)">
          <input
            type="number"
            value={ttlDays}
            onChange={(e) => setTtlDays(Number(e.target.value))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Warn days before">
          <input
            type="number"
            value={warnDays}
            onChange={(e) => setWarnDays(Number(e.target.value))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input type="checkbox" checked={hardExpire} onChange={(e) => setHardExpire(e.target.checked)} />
          Hard expire (block use after TTL)
        </label>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-xs text-red-400">
          {error}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">Cancel</button>
        <button disabled={busy} onClick={submit} className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50">
          {busy ? "Creating…" : "Create"}
        </button>
      </div>
    </FormModal>
  );
}

// ─── Vault Backends Tab ───────────────────────────────────────────────────────

function BackendsTab() {
  const backends = useAsync(() => listVaultBackends(), []);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<VaultBackendResponse | null>(null);

  const cols: ConsoleColumn<VaultBackendResponse>[] = [
    { key: "name", header: "Name", width: "24%", render: (r) => <span className="text-gray-200">{r.name}</span> },
    { key: "type", header: "Backend Type", width: "20%", render: (r) => r.backend_type },
    { key: "default", header: "Default", width: "12%", render: (r) => (r.is_default ? "Yes" : "No") },
    { key: "created", header: "Created", width: "20%", render: (r) => fmtTime(r.created_at) },
    {
      key: "actions",
      header: "Actions",
      width: "24%",
      render: (r) => (
        <button
          onClick={async (e) => {
            e.stopPropagation();
            if (confirm(`Delete vault backend "${r.name}"?`)) {
              await deleteVaultBackend(r.backend_id);
              backends.reload();
            }
          }}
          className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <KpiTile label="Vault Backends" value={backends.data ? backends.data.length : "—"} />
          <KpiTile
            label="Default Backend"
            value={backends.data?.find((b) => b.is_default)?.name ?? "—"}
          />
          <KpiTile
            label="Backend Types"
            value={backends.data ? new Set(backends.data.map((b) => b.backend_type)).size : "—"}
          />
        </div>
        <button onClick={() => setShowCreate(true)} className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50">
          Register Backend
        </button>
      </div>
      <AsyncContent state={backends} empty={(d) => d.length === 0} emptyLabel="No vault backends registered.">
        {(list) => (
          <DataConsole
            columns={cols}
            rows={list}
            rowKey={(r) => r.backend_id}
            onRowClick={setSelected}
            selectedKey={selected?.backend_id}
            emptyLabel="No vault backends registered."
          />
        )}
      </AsyncContent>
      {showCreate && (
        <RegisterBackendModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            backends.reload();
            setShowCreate(false);
          }}
        />
      )}
      {selected && (
        <InvestigationDrawer
          open
          title={selected.name}
          subtitle="Vault Backend"
          entityId={selected.backend_id}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Backend Type", value: selected.backend_type },
            { label: "Default Backend", value: selected.is_default ? "Yes" : "No" },
            { label: "Created / Updated", value: `${fmtTime(selected.created_at)} — ${fmtTime(selected.updated_at)}` },
            {
              label: "Actions",
              value: (
                <button
                  onClick={async () => {
                    if (confirm(`Delete vault backend "${selected.name}"?`)) {
                      await deleteVaultBackend(selected.backend_id);
                      setSelected(null);
                      backends.reload();
                    }
                  }}
                  className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
                >
                  Delete Backend
                </button>
              ),
            },
          ]}
        />
      )}
    </>
  );
}

function RegisterBackendModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [backendType, setBackendType] = useState("");
  const [isDefault, setIsDefault] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!name.trim() || !backendType.trim()) {
      setError("Name and backend type are required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await registerVaultBackend({ name, backend_type: backendType, is_default: isDefault });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to register backend");
    } finally {
      setBusy(false);
    }
  }

  return (
    <FormModal title="Register Vault Backend" onClose={onClose}>
      <div className="space-y-2">
        <FormField label="Backend name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Prod AWS KMS"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <FormField label="Backend type" required>
          <input
            value={backendType}
            onChange={(e) => setBackendType(e.target.value)}
            placeholder="e.g. AWS_KMS, LOCAL"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          />
        </FormField>
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
          Set as default backend
        </label>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-xs text-red-400">
          {error}
        </p>
      )}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">Cancel</button>
        <button disabled={busy} onClick={submit} className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50">
          {busy ? "Registering…" : "Register"}
        </button>
      </div>
    </FormModal>
  );
}
