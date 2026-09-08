"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { listCatalog, type ConnectorPlugin } from "@/lib/integrations";

export default function IntegrationHubPage() {
  const catalog = useAsync(() => listCatalog(), []);
  const [selected, setSelected] = useState<ConnectorPlugin | null>(null);

  const columns: ConsoleColumn<ConnectorPlugin>[] = [
    { key: "name", header: "Integration", width: "28%", render: (r) => (
      <span className="text-gray-200">{r.display_name}</span>
    )},
    { key: "category", header: "Category", width: "18%", render: (r) => r.category },
    { key: "auth", header: "Auth Model", width: "18%", render: (r) => r.auth_model },
    { key: "capabilities", header: "Capabilities", width: "36%", render: (r) => (
      r.capabilities.length > 0 ? r.capabilities.join(", ") : "—"
    )},
  ];

  return (
    <>
      <PageHeader
        title="Integration Hub"
        subtitle="Catalog of available connector plugins — register a connector from the Connectors page to activate one"
        actions={
          <button type="button" onClick={() => catalog.reload()} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300">
            Refresh
          </button>
        }
      />

      <AsyncContent state={catalog}>
        {(plugins) => (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3">
              <KpiTile label="Available Integrations" value={plugins.length} />
              <KpiTile
                label="Categories"
                value={new Set(plugins.map((p) => p.category)).size}
              />
              <KpiTile
                label="With Discovery"
                value={plugins.filter((p) => p.capabilities.includes("discovery")).length}
              />
            </div>
            <DataConsole
              columns={columns}
              rows={plugins}
              rowKey={(r) => r.connector_id}
              onRowClick={(r) => setSelected(r)}
              emptyLabel="No integration plugins available."
            />
          </>
        )}
      </AsyncContent>

      {selected && (
        <InvestigationDrawer
          open
          title={selected.display_name}
          onClose={() => setSelected(null)}
          fields={[
            { label: "Category", value: selected.category },
            { label: "Auth Model", value: selected.auth_model },
            { label: "Capabilities", value: selected.capabilities.join(", ") || "—" },
            { label: "Purpose", value: selected.docs.purpose },
            { label: "Supported Features", value: selected.docs.supported_features.join(", ") || "—" },
            { label: "Required Credentials", value: selected.docs.required_credentials },
            { label: "Required Permissions", value: selected.docs.required_permissions },
          ]}
        />
      )}
    </>
  );
}
