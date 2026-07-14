"use client";

import { useState } from "react";
import {
  getAssetsForPort,
  getCommandOverview,
  getNetworkDrift,
  getServiceExposure,
  getTopOpenPorts,
  type NetworkDriftEvent,
  type PortAsset,
  type PortExposure,
  type ServiceExposure,
} from "@/lib/commandCenter";
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

type Selected =
  | { kind: "port"; row: PortExposure }
  | { kind: "service"; row: ServiceExposure }
  | { kind: "drift"; row: NetworkDriftEvent }
  | null;

export default function NetworkExposurePage() {
  const overview = useAsync(getCommandOverview, []);
  const ports = useAsync(() => getTopOpenPorts(25), []);
  const services = useAsync(() => getServiceExposure(50), []);
  const drift = useAsync(() => getNetworkDrift(50), []);
  const [selected, setSelected] = useState<Selected>(null);
  const portAssets = useAsync<PortAsset[]>(
    () => (selected?.kind === "port" ? getAssetsForPort(selected.row.port) : Promise.resolve([])),
    [selected?.kind === "port" ? selected.row.port : null]
  );

  const runCounts = overview.data?.validation_run_counts ?? {};
  const runTotal = Object.values(runCounts).reduce((a, b) => a + b, 0);

  let drawerFields: DrawerField[] = [];
  let drawerTitle = "";
  let drawerSubtitle = "";
  if (selected?.kind === "port") {
    drawerTitle = `Port ${selected.row.port}/${selected.row.transport}`;
    drawerSubtitle = "Network Operations · open port drill-down";
    drawerFields = [
      { label: "Assets exposed", value: selected.row.asset_count },
      { label: "Observations", value: selected.row.observation_count },
      { label: "Last observed", value: fmtTime(selected.row.last_observed_at) },
      {
        label: "Assets with this port reachable",
        value: (
          <AsyncContent state={portAssets} empty={(a) => a.length === 0} emptyLabel="No assets loaded.">
            {(a) => (
              <ul className="space-y-1">
                {a.map((x) => (
                  <li key={x.asset_id} className="text-xs text-gray-300">
                    {x.asset_name || x.asset_id}{" "}
                    <span className="text-gray-600">
                      ({x.observation_count} obs, last {fmtTime(x.last_observed_at)})
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </AsyncContent>
        ),
      },
    ];
  } else if (selected?.kind === "service") {
    drawerTitle = selected.row.service;
    drawerSubtitle = "Network Operations · validated service";
    drawerFields = [
      { label: "Validator", value: selected.row.validator_id || "—" },
      { label: "Assets", value: selected.row.asset_count },
      { label: "Observations", value: selected.row.observation_count },
      { label: "Last observed", value: fmtTime(selected.row.last_observed_at) },
    ];
  } else if (selected?.kind === "drift") {
    drawerTitle = selected.row.category.replace(/_/g, " ");
    drawerSubtitle = "Network Operations · drift signal";
    drawerFields = [
      { label: "Summary", value: selected.row.summary },
      { label: "Severity", value: <SeverityBadge severity={selected.row.severity} /> },
      { label: "Target asset", value: selected.row.target_asset_name || selected.row.target_asset_id || "—" },
      { label: "Policy", value: selected.row.policy_id },
      { label: "Run", value: selected.row.run_id },
      { label: "Detected at", value: fmtTime(selected.row.detected_at) },
    ];
  }

  return (
    <div>
      <PageHeader
        title="Network Operations Wall"
        subtitle="Open ports, validated services, drift, and monitoring run activity — aggregated only from real M16 network observations. A port appears only if it was observed reachable; a service only if a validator confirmed it."
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiTile label="Open ports tracked" value={ports.data?.length ?? 0} />
        <KpiTile label="Validated services" value={services.data?.length ?? 0} />
        <KpiTile label="Drift signals" value={drift.data?.length ?? 0} tone={(drift.data?.length ?? 0) > 0 ? "warning" : "default"} />
        <KpiTile
          label="Monitoring runs (running)"
          value={runCounts.running ?? 0}
          hint={runTotal > 0 ? `${runTotal} total tracked` : "no runs yet"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Top open ports (observed reachable)">
          <AsyncContent state={ports} empty={(p) => p.length === 0} emptyLabel="No reachable ports observed yet. Run network validation to populate.">
            {(p) => (
              <DataConsole
                rows={p}
                rowKey={(r) => `${r.port}/${r.transport}`}
                onRowClick={(row) => setSelected({ kind: "port", row })}
                selectedKey={selected?.kind === "port" ? `${selected.row.port}/${selected.row.transport}` : null}
                columns={[
                  { key: "port", header: "Port", width: "70px", render: (r) => <span className="font-semibold tabular-nums text-gray-100">{r.port}</span> },
                  { key: "transport", header: "Transport", width: "90px", render: (r) => <span className="uppercase text-gray-400">{r.transport}</span> },
                  { key: "assets", header: "Assets", width: "70px", render: (r) => r.asset_count },
                  { key: "obs", header: "Observations", width: "100px", render: (r) => r.observation_count },
                  { key: "time", header: "Last observed", render: (r) => fmtTime(r.last_observed_at) },
                ]}
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Validated services (protocol confirmed)">
          <AsyncContent state={services} empty={(s) => s.length === 0} emptyLabel="No protocol-validated services observed yet.">
            {(s) => (
              <DataConsole
                rows={s}
                rowKey={(r) => `${r.service}:${r.validator_id}`}
                onRowClick={(row) => setSelected({ kind: "service", row })}
                selectedKey={selected?.kind === "service" ? `${selected.row.service}:${selected.row.validator_id}` : null}
                columns={[
                  { key: "service", header: "Service", render: (r) => <span className="font-semibold text-gray-100">{r.service}</span> },
                  { key: "validator", header: "Validator", render: (r) => r.validator_id || "—" },
                  { key: "assets", header: "Assets", width: "70px", render: (r) => r.asset_count },
                  { key: "obs", header: "Observations", width: "100px", render: (r) => r.observation_count },
                ]}
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Network drift signals">
          <AsyncContent state={drift} empty={(d) => d.length === 0} emptyLabel="No network drift recorded. Drift is detected between monitoring runs.">
            {(d) => (
              <DataConsole
                rows={d}
                rowKey={(r) => r.id}
                onRowClick={(row) => setSelected({ kind: "drift", row })}
                selectedKey={selected?.kind === "drift" ? selected.row.id : null}
                columns={[
                  { key: "sev", header: "Sev", width: "70px", render: (r) => <SeverityBadge severity={r.severity} /> },
                  { key: "category", header: "Category", width: "160px", render: (r) => r.category.replace(/_/g, " ") },
                  { key: "summary", header: "Summary", render: (r) => <span className="text-gray-300">{r.summary}</span> },
                  { key: "target", header: "Target asset", render: (r) => r.target_asset_name || "—" },
                  { key: "time", header: "Detected", render: (r) => fmtTime(r.detected_at) },
                ]}
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Monitoring run activity">
          <AsyncContent state={overview} empty={(o) => Object.keys(o.validation_run_counts).length === 0} emptyLabel="No network monitoring runs recorded yet.">
            {(o) => (
              <div className="space-y-2">
                {Object.entries(o.validation_run_counts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2">
                      <span className="text-xs uppercase tracking-wide text-gray-400">{status.replace(/_/g, " ")}</span>
                      <span className="tabular-nums text-sm font-semibold text-gray-100">{count}</span>
                    </div>
                  ))}
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={drawerTitle}
        subtitle={drawerSubtitle}
        fields={drawerFields}
      />
    </div>
  );
}
