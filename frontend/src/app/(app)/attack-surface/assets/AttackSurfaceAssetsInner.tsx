"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { getExposureStateCoverage, listAssets, type Asset } from "@/lib/attackSurfaceManagement";

const EXPOSURE_LABEL: Record<string, string> = {
  unknown: "Unknown",
  not_exposed: "Not Exposed",
  internet_facing: "Internet Facing",
  exposed_high_risk: "Exposed — High Risk",
};

const CRITICALITY_TONE: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-gray-400",
};

/**
 * Attack Surface Management operational landing page (M49D) —
 * `attack_surface_management`'s real, previously-page-less asset
 * register. Distinct from `/attack-surface` (the separate
 * `securityCorrelations` exposure-concentration correlations page)
 * and from `/assets` (the generic AI/cloud inventory context) — three
 * real bounded contexts, cross-linked, never merged into one page.
 *
 * Platform Intelligence Layer: `?highlight=<asset_id>` auto-opens the
 * matching asset's drawer — the real pivot target for a correlation's
 * `entity_ids` on `/attack-surface` (correlations reference real asset
 * IDs already; this page just makes arriving at one a single click).
 */
export default function AttackSurfaceAssetsInner() {
  const coverage = useAsync(() => getExposureStateCoverage(), []);
  const assets = useAsync(() => listAssets({ limit: 200 }), []);
  const [selected, setSelected] = useState<Asset | null>(null);

  const highlightId = useSearchParams().get("highlight");
  const highlightedOnce = useRef(false);

  useEffect(() => {
    if (!highlightId || highlightedOnce.current || !assets.data) return;
    const target = assets.data.items.find((a) => a.asset_id === highlightId);
    if (!target) return;
    highlightedOnce.current = true;
    setSelected(target);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightId, assets.data]);

  const columns: ConsoleColumn<Asset>[] = [
    {
      key: "identifier",
      header: "Asset",
      width: "26%",
      render: (a) => <span className="font-mono text-gray-200">{a.primary_identifier}</span>,
    },
    { key: "type", header: "Type", width: "12%", render: (a) => a.asset_type },
    {
      key: "exposure",
      header: "Exposure",
      width: "16%",
      render: (a) => (
        <span
          className={
            a.exposure_state === "exposed_high_risk"
              ? "text-red-400"
              : a.exposure_state === "internet_facing"
                ? "text-amber-400"
                : "text-gray-400"
          }
        >
          {EXPOSURE_LABEL[a.exposure_state] ?? a.exposure_state}
        </span>
      ),
    },
    {
      key: "criticality",
      header: "Criticality",
      width: "12%",
      render: (a) => (
        <span className={CRITICALITY_TONE[a.criticality] ?? "text-gray-400"}>{a.criticality}</span>
      ),
    },
    { key: "lifecycle", header: "Lifecycle", width: "12%", render: (a) => <StatusPill status={a.lifecycle_state} /> },
    { key: "ports", header: "Open Ports", width: "10%", render: (a) => a.ports.length },
    {
      key: "owner",
      header: "Owner",
      width: "12%",
      render: (a) => a.ownership?.owning_team ?? "—",
    },
  ];

  return (
    <>
      <PageHeader
        title="Attack Surface Assets"
        subtitle="Discovered external asset register — domains, subdomains, IPs, exposure state, and criticality"
        actions={
          <div className="flex items-center gap-2">
            <Link
              href="/attack-surface"
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-blue-800 hover:text-blue-300"
            >
              View Exposure Correlations →
            </Link>
            <button
              type="button"
              onClick={() => {
                coverage.reload();
                assets.reload();
              }}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-blue-800 hover:text-blue-300"
            >
              Refresh
            </button>
          </div>
        }
      />

      <Panel title="Exposure Coverage" className="mb-6">
        <AsyncContent state={coverage}>
          {(c) => (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Exposed — High Risk" value={c.exposed_high_risk} tone="danger" />
              <KpiTile label="Internet Facing" value={c.internet_facing} tone="warning" />
              <KpiTile label="Not Exposed" value={c.not_exposed} tone="ok" />
              <KpiTile label="Unknown" value={c.unknown} />
            </div>
          )}
        </AsyncContent>
      </Panel>

      <Panel title="Asset Register">
        <AsyncContent state={assets} empty={(a) => a.items.length === 0} emptyLabel="No assets discovered yet.">
          {(a) => (
            <DataConsole
              columns={columns}
              rows={a.items}
              rowKey={(r) => r.asset_id}
              selectedKey={highlightId}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No assets discovered yet."
            />
          )}
        </AsyncContent>
      </Panel>

      {selected && (
        <InvestigationDrawer
          open
          title={selected.primary_identifier}
          subtitle={`${selected.asset_type} · ${selected.discovery_source}`}
          entityId={selected.asset_id}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Exposure State", value: EXPOSURE_LABEL[selected.exposure_state] ?? selected.exposure_state },
            { label: "Criticality", value: selected.criticality },
            { label: "Lifecycle", value: <StatusPill status={selected.lifecycle_state} /> },
            { label: "Classification", value: selected.classification },
            { label: "Domain", value: selected.domain_name ?? "—" },
            { label: "Subdomain", value: selected.subdomain ?? "—" },
            { label: "IP Address", value: selected.ip_address ?? "—" },
            {
              label: "Owner",
              value: selected.ownership
                ? `${selected.ownership.owning_team ?? "—"}${selected.ownership.contact ? ` (${selected.ownership.contact})` : ""}`
                : "Unassigned",
            },
            {
              label: `Open Ports (${selected.ports.length})`,
              value:
                selected.ports.length === 0 ? (
                  "—"
                ) : (
                  <div className="space-y-1">
                    {selected.ports.map((p) => (
                      <div key={p.port_id} className="flex items-center justify-between rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs">
                        <span className={p.is_high_risk ? "text-red-400" : "text-gray-300"}>
                          {p.port_number}/{p.protocol} {p.service_name ?? ""}
                        </span>
                        <span className="text-gray-600">{p.state}</span>
                      </div>
                    ))}
                  </div>
                ),
            },
            {
              label: `Technology Fingerprints (${selected.fingerprints.length})`,
              value:
                selected.fingerprints.length === 0 ? (
                  "—"
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {selected.fingerprints.map((f, i) => (
                      <span key={i} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">
                        {f.name}
                        {f.version ? ` ${f.version}` : ""}
                      </span>
                    ))}
                  </div>
                ),
            },
            {
              label: `Certificates (${selected.certificates.length})`,
              value:
                selected.certificates.length === 0 ? (
                  "—"
                ) : (
                  <div className="space-y-1">
                    {selected.certificates.map((c) => (
                      <div key={c.certificate_id} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs">
                        <div className="text-gray-300">{c.common_name}</div>
                        <div className="text-gray-600">
                          {c.issuer} · expires {new Date(c.not_after).toLocaleDateString()} · {c.status}
                        </div>
                      </div>
                    ))}
                  </div>
                ),
            },
          ]}
        />
      )}
    </>
  );
}
