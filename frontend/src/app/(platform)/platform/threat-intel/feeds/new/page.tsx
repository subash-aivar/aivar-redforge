"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { registerFeed, SOURCE_KIND_LABELS } from "@/lib/feedSync";

const SOURCE_KINDS = Object.keys(SOURCE_KIND_LABELS);

export default function RegisterFeedPage() {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const [feedKey, setFeedKey] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [sourceKind, setSourceKind] = useState("");
  const [intervalSeconds, setIntervalSeconds] = useState(3600);
  const [scope, setScope] = useState("global");
  const [credentialRef, setCredentialRef] = useState("");
  const [configRaw, setConfigRaw] = useState("{}");
  const [configError, setConfigError] = useState("");

  function validateConfig(raw: string) {
    try {
      JSON.parse(raw);
      setConfigError("");
      return true;
    } catch {
      setConfigError("Invalid JSON");
      return false;
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!validateConfig(configRaw)) return;
    setSubmitting(true);
    setError("");
    try {
      await registerFeed({
        feed_key: feedKey.trim(),
        display_name: displayName.trim(),
        source_kind: sourceKind,
        interval_seconds: intervalSeconds,
        scope,
        credential_ref: credentialRef.trim() || null,
        connector_config: JSON.parse(configRaw),
      });
      router.push("/platform/threat-intel/feeds");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || "Failed to register feed.");
      setSubmitting(false);
    }
  }

  return (
    <div className="max-w-xl">
      <h1 className="text-2xl font-bold text-white">Register Feed</h1>
      <p className="mt-1 text-sm text-gray-400">
        Connect a new threat intelligence data source.
      </p>

      <form onSubmit={submit} className="mt-6 space-y-5">
        <Field label="Feed Key" hint="Unique identifier, e.g. mitre_attack_v15">
          <input
            required
            value={feedKey}
            onChange={(e) => setFeedKey(e.target.value)}
            placeholder="mitre_attack_v15"
            className={inputClass}
          />
        </Field>

        <Field label="Display Name">
          <input
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="MITRE ATT&CK v15"
            className={inputClass}
          />
        </Field>

        <Field label="Source Kind">
          <select
            required
            value={sourceKind}
            onChange={(e) => setSourceKind(e.target.value)}
            className={inputClass}
          >
            <option value="">Select…</option>
            {SOURCE_KINDS.map((k) => (
              <option key={k} value={k}>{SOURCE_KIND_LABELS[k]}</option>
            ))}
          </select>
        </Field>

        <Field label="Sync Interval (seconds)" hint="How often to poll the source">
          <input
            type="number"
            required
            min={60}
            value={intervalSeconds}
            onChange={(e) => setIntervalSeconds(Number(e.target.value))}
            className={inputClass}
          />
        </Field>

        <Field label="Scope">
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            className={inputClass}
          >
            <option value="global">Global</option>
            <option value="platform">Platform</option>
          </select>
        </Field>

        <Field label="Credential Ref" hint="Optional — reference to a stored credential">
          <input
            value={credentialRef}
            onChange={(e) => setCredentialRef(e.target.value)}
            placeholder="cred_abc123"
            className={inputClass}
          />
        </Field>

        <Field
          label="Connector Config (JSON)"
          hint="Source-specific configuration object"
          error={configError}
        >
          <textarea
            rows={6}
            value={configRaw}
            onChange={(e) => { setConfigRaw(e.target.value); validateConfig(e.target.value); }}
            className={`${inputClass} font-mono text-xs`}
          />
        </Field>

        {error && (
          <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="flex gap-3">
          <button
            type="submit"
            disabled={submitting}
            className="rounded-lg bg-purple-700 px-5 py-2 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
          >
            {submitting ? "Registering…" : "Register Feed"}
          </button>
          <button
            type="button"
            onClick={() => router.back()}
            className="rounded-lg border border-gray-700 px-5 py-2 text-sm text-gray-400 hover:text-gray-200"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-purple-600";

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-gray-300">
        {label}
        {hint && <p className="mb-1 text-xs text-gray-600">{hint}</p>}
        {children}
      </label>
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
    </div>
  );
}
