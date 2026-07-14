"use client";

import { useState } from "react";
import {
  INTEGRATION_LABELS,
  disableIntegration,
  listIntegrations,
  registerIntegration,
  type IntegrationStatus,
} from "@/lib/commandCenter";
import { ApiError } from "@/lib/api";
import {
  KpiTile,
  NotConfigured,
  Panel,
  PageHeader,
  StatusPill,
  fmtTime,
  useAsync,
} from "@/components/cc";

function RegisterForm({
  integrationType,
  onRegistered,
}: {
  integrationType: string;
  onRegistered: () => void;
}) {
  const [providerName, setProviderName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!providerName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await registerIntegration(integrationType, providerName.trim());
      setProviderName("");
      onRegistered();
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        setError("You don't have permission to register a provider. An organization administrator can.");
      } else {
        setError(e instanceof Error ? e.message : "Registration failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 flex items-center gap-2">
      <input
        type="text"
        value={providerName}
        onChange={(e) => setProviderName(e.target.value)}
        placeholder="Provider name (e.g. Cloudflare, Palo Alto)"
        className="flex-1 rounded-md border border-gray-800 bg-gray-950/80 px-2.5 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
      />
      <button
        type="button"
        disabled={busy || !providerName.trim()}
        onClick={submit}
        className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 disabled:opacity-40"
      >
        Register
      </button>
      {error && <span className="text-[11px] text-red-400">{error}</span>}
    </div>
  );
}

function IntegrationCard({ s, onChanged }: { s: IntegrationStatus; onChanged: () => void }) {
  const label = INTEGRATION_LABELS[s.integration_type] ?? s.integration_type;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function disable() {
    setBusy(true);
    setError(null);
    try {
      await disableIntegration(s.integration_type);
      onChanged();
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        setError("You don't have permission to remove this provider.");
      } else {
        setError(e instanceof Error ? e.message : "Removal failed");
      }
    } finally {
      setBusy(false);
    }
  }

  if (s.status === "not_configured") {
    return (
      <Panel title={label}>
        <NotConfigured label={label} detail={s.detail} />
        <RegisterForm integrationType={s.integration_type} onRegistered={onChanged} />
      </Panel>
    );
  }
  return (
    <Panel title={label} right={<StatusPill status={s.status} />}>
      <div className="space-y-1.5 text-sm">
        <div className="flex justify-between">
          <span className="text-gray-500">Provider</span>
          <span className="text-gray-200">{s.provider_name ?? "—"}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-500">Last telemetry</span>
          <span className="text-gray-200">{fmtTime(s.last_telemetry_at)}</span>
        </div>
        <div
          className={`mt-2 rounded border px-3 py-2 text-xs ${
            s.status === "awaiting_telemetry"
              ? "border-sky-900/60 bg-sky-950/30 text-sky-300"
              : "border-emerald-900/60 bg-emerald-950/30 text-emerald-300"
          }`}
        >
          {s.detail} No metric values are shown until real telemetry is received — the
          platform never synthesizes them.
        </div>
        <div className="mt-2 flex items-center justify-between">
          <button
            type="button"
            disabled={busy}
            onClick={disable}
            className="rounded-md border border-gray-800 px-2.5 py-1 text-[11px] text-gray-400 hover:border-red-900 hover:text-red-300 disabled:opacity-40"
          >
            Remove provider
          </button>
          {error && <span className="text-[11px] text-red-400">{error}</span>}
        </div>
      </div>
    </Panel>
  );
}

export default function IntegrationsPage() {
  const integrations = useAsync(listIntegrations, []);

  const counts = { not_configured: 0, awaiting_telemetry: 0, active: 0 };
  for (const s of integrations.data ?? []) {
    if (s.status in counts) counts[s.status as keyof typeof counts]++;
  }

  return (
    <div>
      <PageHeader
        title="Telemetry / Integration Wall"
        subtitle="Provider-neutral boundaries for external telemetry (firewall/IDS, network bandwidth/flow, ISP connectivity, backup & DR, threat intelligence, geolocation). Each shows NOT CONFIGURED until a real provider is wired, and AWAITING TELEMETRY until it reports — the platform never fabricates telemetry."
      />

      <div className="mb-4 grid grid-cols-3 gap-3">
        <KpiTile label="Not configured" value={counts.not_configured} />
        <KpiTile label="Awaiting telemetry" value={counts.awaiting_telemetry} tone="warning" />
        <KpiTile label="Active" value={counts.active} tone={counts.active > 0 ? "ok" : "default"} />
      </div>

      {integrations.loading ? (
        <div className="py-10 text-center text-sm text-gray-500">Loading…</div>
      ) : integrations.forbidden ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-6 text-center text-sm text-gray-400">
          You don&apos;t have permission to view integrations.
        </div>
      ) : integrations.error ? (
        <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {integrations.error}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(integrations.data ?? []).map((s) => (
            <IntegrationCard key={s.integration_type} s={s} onChanged={integrations.reload} />
          ))}
        </div>
      )}
    </div>
  );
}
