"use client";

import { useMemo, useState } from "react";
import { listSecurityObservations, type SecurityObservation } from "@/lib/directorySecurity";
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

export default function IdentitySecurityPage() {
  const state = useAsync(() => listSecurityObservations(), []);
  const [selected, setSelected] = useState<SecurityObservation | null>(null);

  const columns: ConsoleColumn<SecurityObservation>[] = useMemo(
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
        { label: "Affected Identity ID", value: selected.affected_identity_id },
        { label: "Affected Group ID", value: selected.affected_group_id ?? "—" },
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="Identity Security"
        subtitle="Deterministic security observations over canonical directory identity
          state — exposure context, not confirmed vulnerabilities or compromise."
      />

      <AsyncContent
        state={state}
        empty={(data) => data.length === 0}
        emptyLabel="No security observations."
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
                <DataConsole<SecurityObservation>
                  columns={columns}
                  rows={observations}
                  rowKey={(o) => `${o.rule_id}:${o.affected_identity_id}`}
                  onRowClick={(o) => setSelected(o)}
                  selectedKey={
                    selected ? `${selected.rule_id}:${selected.affected_identity_id}` : null
                  }
                  emptyLabel="No security observations."
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
        entityId={selected?.affected_identity_id}
        fields={drawerFields}
        links={selected ? [{ label: "View in Identities", href: "/identities" }] : []}
      />
    </div>
  );
}
