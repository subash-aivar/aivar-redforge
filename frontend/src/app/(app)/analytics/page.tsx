"use client";

import {
  AsyncContent,
  DataConsole,
  KpiTile,
  PageHeader,
  Panel,
  SeverityBadge,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import { getSummary, listAnomalies, type AnalyticsAnomaly } from "@/lib/analytics";

export default function AnalyticsPage() {
  const summary = useAsync(() => getSummary(), []);
  const anomalies = useAsync(() => listAnomalies(), []);

  const columns: ConsoleColumn<AnalyticsAnomaly>[] = [
    { key: "signal", header: "Signal Type", width: "22%", render: (r) => r.signal_type },
    { key: "severity", header: "Severity", width: "14%", render: (r) => <SeverityBadge severity={r.severity} /> },
    { key: "score", header: "Score", width: "14%", render: (r) => (
      <span className="tabular-nums">{r.score.toFixed(2)}</span>
    ) },
    { key: "observed", header: "Observed", width: "14%", render: (r) => (
      <span className="tabular-nums">{r.observed}</span>
    ) },
    { key: "method", header: "Method", width: "18%", render: (r) => r.method },
    { key: "detected", header: "Detected", width: "18%", render: (r) => fmtTime(r.detected_at) },
  ];

  return (
    <>
      <PageHeader
        title="Analytics"
        subtitle="KPI trends and anomaly detection across the security program"
        actions={
          <button
            type="button"
            onClick={() => {
              summary.reload();
              anomalies.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <AsyncContent state={summary} emptyLabel="No analytics data yet.">
        {(data) => (
          <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiTile label="Datasets" value={data.datasets} />
            <KpiTile
              label="Anomalies"
              value={data.anomaly_count}
              tone={data.anomaly_count > 0 ? "warning" : "ok"}
            />
            {data.kpis.slice(0, 2).map((k) => (
              <KpiTile
                key={k.kpi_type}
                label={k.kpi_type}
                value={k.latest_value ?? "—"}
                hint={k.status}
              />
            ))}
          </div>
        )}
      </AsyncContent>

      {summary.data && summary.data.kpis.length > 2 && (
        <Panel title="KPI Snapshots" className="mb-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {summary.data.kpis.map((k) => (
              <KpiTile key={k.kpi_type} label={k.kpi_type} value={k.latest_value ?? "—"} hint={k.status} />
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Recent Anomalies">
        <AsyncContent state={anomalies} emptyLabel="No anomalies detected.">
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows}
              rowKey={(r) => `${r.signal_type}-${r.detected_at}`}
              emptyLabel="No anomalies detected."
            />
          )}
        </AsyncContent>
      </Panel>
    </>
  );
}
