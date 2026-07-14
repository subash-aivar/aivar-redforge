"use client";

import { useMemo, useState } from "react";
import { getBehaviorSignals, type BehaviorSignal } from "@/lib/commandCenter";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  Panel,
  PageHeader,
  SeverityBadge,
  fmtTime,
  useAsync,
  type DrawerField,
} from "@/components/cc";

const PERIODS = ["1h", "24h", "7d", "30d"] as const;

const SECTIONS: { domain: string; label: string; acronym: string; detail: string }[] = [
  {
    domain: "user",
    label: "User Behavior Analytics",
    acronym: "UEBA",
    detail: "Deterministic thresholds over the administrative audit log (e.g. admin action volume, privilege changes). Login/auth-attempt signals require a queryable auth audit table — not yet available.",
  },
  {
    domain: "host",
    label: "Host Behavior Analytics",
    acronym: "HBA",
    detail: "Deterministic signals derived from real host/asset security-drift categories.",
  },
  {
    domain: "network",
    label: "Network Behavior Analytics",
    acronym: "NBA",
    detail: "Deterministic signals derived from real network-drift categories (M16).",
  },
];

function SignalConsole({
  signals,
  onSelect,
  selectedKey,
}: {
  signals: BehaviorSignal[];
  onSelect: (s: BehaviorSignal) => void;
  selectedKey: string | null;
}) {
  return (
    <DataConsole
      rows={signals}
      rowKey={(s) => `${s.signal_type}:${s.subject}:${s.observed_window}`}
      onRowClick={onSelect}
      selectedKey={selectedKey}
      emptyLabel="No signals in this window. Signals appear only when real evidence crosses a documented, deterministic threshold."
      columns={[
        { key: "sev", header: "Sev", width: "70px", render: (s) => <SeverityBadge severity={s.severity} /> },
        { key: "type", header: "Signal", width: "180px", render: (s) => s.signal_type.replace(/_/g, " ") },
        { key: "subject", header: "Subject", width: "160px", render: (s) => <span className="font-mono text-[11px]">{s.subject}</span> },
        { key: "summary", header: "Summary", render: (s) => <span className="text-gray-300">{s.summary}</span> },
        { key: "evidence", header: "Evidence", width: "90px", render: (s) => s.evidence_count },
        { key: "window", header: "Window", width: "90px", render: (s) => s.observed_window },
      ]}
    />
  );
}

export default function BehaviorAnalyticsPage() {
  const [period, setPeriod] = useState<(typeof PERIODS)[number]>("24h");
  const signals = useAsync(() => getBehaviorSignals(period, undefined), [period]);
  const [selected, setSelected] = useState<{ domain: string; sig: BehaviorSignal } | null>(null);

  const byDomain = useMemo(() => {
    const map: Record<string, BehaviorSignal[]> = { user: [], host: [], network: [] };
    for (const s of signals.data ?? []) {
      (map[s.domain] ?? (map[s.domain] = [])).push(s);
    }
    return map;
  }, [signals.data]);

  const drawerFields: DrawerField[] = selected
    ? [
        { label: "Domain", value: selected.sig.domain },
        { label: "Signal type", value: selected.sig.signal_type.replace(/_/g, " ") },
        { label: "Severity", value: <SeverityBadge severity={selected.sig.severity} /> },
        { label: "Subject", value: selected.sig.subject },
        { label: "Summary", value: selected.sig.summary },
        { label: "Observed window", value: selected.sig.observed_window },
        { label: "Evidence count", value: selected.sig.evidence_count },
        {
          label: "Evidence (source-linked)",
          value: (
            <div className="space-y-1.5">
              {selected.sig.evidence.map((ev, i) => (
                <div key={i} className="rounded border border-gray-800 bg-gray-900/50 p-2 text-xs">
                  <div className="text-gray-500">
                    {ev.source} · <span className="font-mono">{ev.source_id}</span> · {fmtTime(ev.occurred_at)}
                  </div>
                  <div className="mt-0.5 text-gray-300">{ev.detail}</div>
                </div>
              ))}
            </div>
          ),
        },
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="Behavior Analytics Wall"
        subtitle="Deterministic, fully-explainable UEBA / HBA / NBA signals. Every signal is a fixed rule over real audit or drift rows — no ML, no probability score, no fabricated confidence — and lists the exact source records that produced it."
        actions={
          <div className="flex gap-1">
            {PERIODS.map((p) => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`rounded px-2.5 py-1 text-xs ${period === p ? "bg-gray-700 text-gray-100" : "bg-gray-800 text-gray-400 hover:text-gray-200"}`}
              >
                {p}
              </button>
            ))}
          </div>
        }
      />

      <div className="mb-4 grid grid-cols-3 gap-3">
        {SECTIONS.map((sec) => (
          <KpiTile
            key={sec.domain}
            label={sec.acronym}
            value={byDomain[sec.domain]?.length ?? 0}
            hint={sec.label}
            tone={(byDomain[sec.domain]?.length ?? 0) > 0 ? "warning" : "default"}
          />
        ))}
      </div>

      <AsyncContent state={signals}>
        {() => (
          <div className="space-y-4">
            {SECTIONS.map((sec) => (
              <Panel
                key={sec.domain}
                title={`${sec.label} (${sec.acronym}) — deterministic, explainable analytics`}
              >
                <p className="mb-3 text-xs text-gray-500">{sec.detail}</p>
                <SignalConsole
                  signals={byDomain[sec.domain] ?? []}
                  onSelect={(sig) => setSelected({ domain: sec.domain, sig })}
                  selectedKey={
                    selected && selected.domain === sec.domain
                      ? `${selected.sig.signal_type}:${selected.sig.subject}:${selected.sig.observed_window}`
                      : null
                  }
                />
              </Panel>
            ))}
          </div>
        )}
      </AsyncContent>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.sig.summary ?? ""}
        subtitle={selected ? `Behavior signal · ${selected.sig.domain}` : ""}
        fields={drawerFields}
      />
    </div>
  );
}
