"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  listIntegrations,
  enableIntegration,
  disableIntegration,
  syncIntegration,
  type Integration,
} from "@/lib/integrationHub";

export default function IntegrationHubPage() {
  const integrations = useAsync(() => listIntegrations(), []);
  const [selected, setSelected] = useState<Integration | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleToggle(integration: Integration) {
    setBusy(true);
    try {
      if (integration.status === "active" || integration.status === "enabled") {
        await disableIntegration(integration.integration_id);
      } else {
        await enableIntegration(integration.integration_id);
      }
      integrations.reload();
      setSelected(null);
    } finally {
      setBusy(false);
    }
  }

  async function handleSync(integration: Integration) {
    setBusy(true);
    try {
      await syncIntegration(integration.integration_id);
      integrations.reload();
    } finally {
      setBusy(false);
    }
  }

  const columns: ConsoleColumn<Integration>[] = [
    { key: "name", header: "Integration", width: "24%", render: (r) => (
      <span className="text-gray-200">{r.name}</span>
    )},
    { key: "type", header: "Type", width: "16%", render: (r) => r.integration_type },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "synced", header: "Last Synced", width: "18%", render: (r) => fmtTime(r.last_synced_at) },
    { key: "created", header: "Created", width: "16%", render: (r) => fmtTime(r.created_at) },
    { key: "id", header: "ID", width: "14%", render: (r) => (
      <span className="font-mono text-[10px] text-gray-600">{r.integration_id.slice(0, 10)}…</span>
    )},
  ];

  return (
    <>
      <PageHeader
        title="Integration Hub"
        subtitle="Connected services, data sources, and external platform integrations"
        actions={
          <button type="button" onClick={() => integrations.reload()} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300">
            Refresh
          </button>
        }
      />

      <AsyncContent state={integrations}>
        {(list) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <KpiTile label="Total" value={list.length} />
              <KpiTile label="Active" value={list.filter(i => i.status === "active" || i.status === "enabled").length} tone="ok" />
              <KpiTile label="Disabled" value={list.filter(i => i.status === "disabled" || i.status === "inactive").length} tone="warning" />
              <KpiTile label="Error" value={list.filter(i => i.status === "error").length} tone="danger" />
            </div>
            <DataConsole
              columns={columns}
              rows={list}
              rowKey={(r) => r.integration_id}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No integrations configured. Connect external services to enrich security intelligence."
            />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          title={selected.name}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Type", value: selected.integration_type },
            { label: "Status", value: <StatusPill status={selected.status} /> },
            { label: "Last Synced", value: fmtTime(selected.last_synced_at) },
            { label: "Created", value: fmtTime(selected.created_at) },
            {
              label: "Actions",
              value: (
                <div className="flex gap-2">
                  <button
                    onClick={() => handleToggle(selected)}
                    disabled={busy}
                    className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
                  >
                    {selected.status === "active" || selected.status === "enabled" ? "Disable" : "Enable"}
                  </button>
                  <button
                    onClick={() => handleSync(selected)}
                    disabled={busy}
                    className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-50"
                  >
                    Sync Now
                  </button>
                </div>
              ),
            },
          ]}
        />
      )}
    </>
  );
}
