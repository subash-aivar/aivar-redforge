"use client";

import { useMemo, useState } from "react";
import { listCloudSecurityObservations, type CloudSecurityObservation } from "@/lib/cloudSecurity";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";

export default function CloudSecurityPage() {
  const state = useAsync(() => listCloudSecurityObservations(), []);
  const [selected, setSelected] = useState<CloudSecurityObservation | null>(null);

  const columns: ConsoleColumn<CloudSecurityObservation>[] = useMemo(
    () => [
      {
        key: "rule_id",
        header: "Rule ID",
        width: "160px",
        render: (o) => (
          <span className="rounded bg-amber-950 px-2 py-0.5 font-mono text-xs text-amber-400">
            {o.rule_id}
          </span>
        ),
      },
      {
        key: "title",
        header: "Title",
        render: (o) => <span className="text-sm font-medium text-gray-200">{o.title}</span>,
      },
      {
        key: "summary",
        header: "Summary",
        render: (o) => (
          <span className="line-clamp-1 max-w-[520px] truncate text-sm text-gray-400" title={o.summary}>
            {o.summary}
          </span>
        ),
      },
    ],
    []
  );

  const drawerFields: DrawerField[] = selected
    ? [
        { label: "Rule ID", value: selected.rule_id },
        { label: "Title", value: selected.title },
        { label: "Summary", value: selected.summary },
        { label: "Affected Asset ID", value: selected.affected_asset_id },
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="Cloud Security"
        subtitle="Deterministic observations over discovered cloud accounts/resources —
          exposure context, not confirmed vulnerabilities or CVEs. AWS is the
          only implemented provider; Azure/GCP are not yet supported. Browse
          discovered accounts/resources on the Assets page (filter by kind)."
      />

      <AsyncContent
        state={state}
        empty={(data) => data.length === 0}
        emptyLabel="No cloud exposure observations. Register an AWS connector and run discovery."
      >
        {(observations) => {
          const distinctRuleCount = new Set(observations.map((o) => o.rule_id)).size;
          return (
            <>
              <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
                <KpiTile label="Total observations" value={observations.length} />
                <KpiTile label="Distinct rule types" value={distinctRuleCount} />
              </div>

              <Panel title="Observations">
                <DataConsole<CloudSecurityObservation>
                  columns={columns}
                  rows={observations}
                  rowKey={(o) => `${o.rule_id}:${o.affected_asset_id}`}
                  onRowClick={(o) => setSelected(o)}
                  selectedKey={selected ? `${selected.rule_id}:${selected.affected_asset_id}` : null}
                  emptyLabel="No cloud exposure observations. Register an AWS connector and run discovery."
                />
              </Panel>
            </>
          );
        }}
      </AsyncContent>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.title ?? ""}
        subtitle={selected?.rule_id}
        entityId={selected?.affected_asset_id}
        fields={drawerFields}
        links={selected ? [{ label: "View in Assets", href: "/assets" }] : []}
      />
    </div>
  );
}
