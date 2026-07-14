"use client";

import { useState } from "react";
import {
  listTelemetryEvents,
  listSensors,
  getBandwidthSummary,
  type TelemetryEvent,
  type Sensor,
  type BandwidthSummary,
} from "@/lib/telemetry";
import {
  AsyncContent,
  DataConsole,
  FilterChip,
  InvestigationDrawer,
  Panel,
  PageHeader,
  SeverityBadge,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-sky-400",
  info: "text-gray-400",
};

const EVENT_TYPE_LABELS: Record<string, string> = {
  suricata_alert: "Alert",
  suricata_flow: "Flow",
  suricata_netflow: "NetFlow",
  suricata_dns: "DNS",
  suricata_http: "HTTP",
  suricata_tls: "TLS",
  zeek_conn: "Conn",
  zeek_notice: "Notice",
  zeek_ssl: "SSL",
  zeek_dns: "DNS",
};

function fmtBytes(n: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTs(ts: string): string {
  return new Date(ts).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

const EVENT_COLUMNS: ConsoleColumn<TelemetryEvent>[] = [
  {
    key: "ts",
    header: "Time",
    width: "90px",
    render: (e) => (
      <span className="font-mono text-gray-500">{fmtTs(e.event_ts)}</span>
    ),
  },
  {
    key: "type",
    header: "Type",
    width: "90px",
    render: (e) => (
      <span className="text-gray-400">
        {EVENT_TYPE_LABELS[e.event_type] ?? e.event_type}
      </span>
    ),
  },
  {
    key: "severity",
    header: "Sev",
    width: "70px",
    render: (e) =>
      e.severity ? (
        <span className={SEVERITY_COLOR[e.severity.toLowerCase()] ?? "text-gray-400"}>
          {e.severity}
        </span>
      ) : (
        <span className="text-gray-600">—</span>
      ),
  },
  {
    key: "src",
    header: "Source",
    width: "160px",
    render: (e) => (
      <span className="font-mono text-[11px] text-gray-300">
        {e.src_ip ? `${e.src_ip}${e.src_port ? `:${e.src_port}` : ""}` : "—"}
      </span>
    ),
  },
  {
    key: "dst",
    header: "Destination",
    width: "160px",
    render: (e) => (
      <span className="font-mono text-[11px] text-gray-300">
        {e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}` : "—"}
      </span>
    ),
  },
  {
    key: "sig",
    header: "Signature / Detail",
    render: (e) => (
      <span className="text-gray-300">
        {e.signature
          ? e.signature.length > 72
            ? `${e.signature.slice(0, 72)}…`
            : e.signature
          : e.action ?? "—"}
      </span>
    ),
  },
  {
    key: "sensor",
    header: "Sensor",
    width: "100px",
    render: (e) => (
      <span className="text-[11px] text-gray-500">{e.sensor_name}</span>
    ),
  },
];

export default function FirewallIDSWallPage() {
  const sensors = useAsync<Sensor[]>(() => listSensors(), []);
  const bandwidth = useAsync<BandwidthSummary>(
    () => getBandwidthSummary(24),
    [],
  );
  const events = useAsync<TelemetryEvent[]>(
    () => listTelemetryEvents({ limit: 200 }),
    [],
  );

  const [sensorFilter, setSensorFilter] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filteredEvents = (events.data ?? []).filter((e) => {
    if (sensorFilter && e.sensor_id !== sensorFilter) return false;
    if (typeFilter && e.event_type !== typeFilter) return false;
    return true;
  });

  const eventTypes = Array.from(
    new Set((events.data ?? []).map((e) => e.event_type)),
  ).sort();

  const selected =
    selectedId != null
      ? (events.data ?? []).find((e) => e.id === selectedId) ?? null
      : null;

  const drawerFields: DrawerField[] = selected
    ? [
        {
          label: "Event type",
          value:
            EVENT_TYPE_LABELS[selected.event_type] ?? selected.event_type,
        },
        { label: "Format", value: selected.format },
        { label: "Sensor", value: selected.sensor_name },
        {
          label: "Severity",
          value: selected.severity ? (
            <SeverityBadge severity={selected.severity} />
          ) : (
            "—"
          ),
        },
        {
          label: "Event time",
          value: new Date(selected.event_ts).toLocaleString(),
        },
        { label: "Signature", value: selected.signature ?? "—" },
        { label: "Signature ID", value: selected.signature_id ?? "—" },
        { label: "Action", value: selected.action ?? "—" },
        {
          label: "Source",
          value: selected.src_ip
            ? `${selected.src_ip}${selected.src_port ? `:${selected.src_port}` : ""}`
            : "—",
        },
        {
          label: "Destination",
          value: selected.dst_ip
            ? `${selected.dst_ip}${selected.dst_port ? `:${selected.dst_port}` : ""}`
            : "—",
        },
        { label: "Protocol", value: selected.protocol ?? "—" },
        { label: "Bytes in", value: fmtBytes(selected.bytes_in) },
        { label: "Bytes out", value: fmtBytes(selected.bytes_out) },
        {
          label: "Packets in",
          value: selected.packets_in != null ? String(selected.packets_in) : "—",
        },
        {
          label: "Packets out",
          value: selected.packets_out != null ? String(selected.packets_out) : "—",
        },
        { label: "Enrichment state", value: selected.enrichment_state },
        {
          label: "Ingested at",
          value: new Date(selected.ingested_at).toLocaleString(),
        },
        {
          label: "Source event ID",
          value: (
            <span className="font-mono text-[10px]">
              {selected.source_event_id}
            </span>
          ),
        },
      ]
    : [];

  const bw = bandwidth.data;

  return (
    <div>
      <PageHeader
        title="Firewall / IDS Operations Wall"
        subtitle="Real telemetry events ingested from customer-owned Suricata and Zeek sensors. Data shown only when sensors are registered and events have been ingested."
      />

      {/* Bandwidth KPIs — only shown when real data exists */}
      {bw && bw.has_real_data && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            {
              label: "Total bytes in (24h)",
              value: fmtBytes(bw.total_bytes_in),
            },
            {
              label: "Total bytes out (24h)",
              value: fmtBytes(bw.total_bytes_out),
            },
            { label: "Flows (24h)", value: bw.flow_count.toLocaleString() },
            {
              label: "Active sensors",
              value: (sensors.data ?? []).filter((s) => s.enabled).length,
            },
          ].map(({ label, value }) => (
            <div
              key={label}
              className="rounded-lg border border-gray-800 bg-gray-950/60 p-3"
            >
              <div className="text-2xl font-semibold tabular-nums text-gray-100">
                {value}
              </div>
              <div className="mt-0.5 text-xs text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Top talkers + top ports — only when real data */}
      {bw && bw.has_real_data && (
        <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Panel>
            <div className="mb-2 text-sm font-medium text-gray-300">
              Top Talkers (24h)
            </div>
            {bw.top_talkers.length === 0 ? (
              <p className="text-xs text-gray-600">No traffic data.</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="py-1 text-left font-normal">Source IP</th>
                    <th className="py-1 text-right font-normal">Bytes sent</th>
                    <th className="py-1 text-right font-normal">Flows</th>
                  </tr>
                </thead>
                <tbody>
                  {bw.top_talkers.slice(0, 8).map((t) => (
                    <tr key={t.src_ip} className="border-t border-gray-800">
                      <td className="py-1 font-mono text-gray-300">
                        {t.src_ip}
                      </td>
                      <td className="py-1 text-right text-gray-400">
                        {fmtBytes(t.bytes_sent)}
                      </td>
                      <td className="py-1 text-right text-gray-500">
                        {t.flow_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel>
            <div className="mb-2 text-sm font-medium text-gray-300">
              Top Destination Ports (24h)
            </div>
            {bw.top_destination_ports.length === 0 ? (
              <p className="text-xs text-gray-600">No traffic data.</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500">
                    <th className="py-1 text-left font-normal">Port</th>
                    <th className="py-1 text-left font-normal">Protocol</th>
                    <th className="py-1 text-right font-normal">Events</th>
                  </tr>
                </thead>
                <tbody>
                  {bw.top_destination_ports.slice(0, 8).map((p) => (
                    <tr
                      key={`${p.dst_port}-${p.protocol}`}
                      className="border-t border-gray-800"
                    >
                      <td className="py-1 font-mono text-gray-300">
                        {p.dst_port}
                      </td>
                      <td className="py-1 text-gray-400">
                        {p.protocol ?? "—"}
                      </td>
                      <td className="py-1 text-right text-gray-500">
                        {p.event_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>
      )}

      {/* Event console */}
      <Panel>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-gray-300">
            IDS / Firewall Events
          </span>
          <FilterChip
            label="All sensors"
            active={sensorFilter === null}
            onClick={() => setSensorFilter(null)}
          />
          {(sensors.data ?? []).map((s) => (
            <FilterChip
              key={s.id}
              label={s.name}
              active={sensorFilter === s.id}
              onClick={() =>
                setSensorFilter(sensorFilter === s.id ? null : s.id)
              }
            />
          ))}
          {eventTypes.length > 0 && (
            <>
              <span className="h-4 w-px bg-gray-800" />
              <FilterChip
                label="All types"
                active={typeFilter === null}
                onClick={() => setTypeFilter(null)}
              />
              {eventTypes.map((t) => (
                <FilterChip
                  key={t}
                  label={EVENT_TYPE_LABELS[t] ?? t}
                  active={typeFilter === t}
                  onClick={() =>
                    setTypeFilter(typeFilter === t ? null : t)
                  }
                />
              ))}
            </>
          )}
        </div>

        <AsyncContent
          state={events}
          empty={(d) => d.length === 0}
          emptyLabel="No telemetry events yet. Register a Suricata or Zeek sensor and start ingesting data via POST /api/v1/telemetry/ingest."
        >
          {() => (
            <DataConsole
              columns={EVENT_COLUMNS}
              rows={filteredEvents}
              rowKey={(e) => e.id}
              selectedKey={selectedId}
              onRowClick={(e) =>
                setSelectedId(selectedId === e.id ? null : e.id)
              }
            />
          )}
        </AsyncContent>
      </Panel>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelectedId(null)}
        title={selected?.signature ?? selected?.event_type ?? ""}
        subtitle={`Firewall / IDS · ${selected ? new Date(selected.event_ts).toLocaleString() : ""}`}
        fields={drawerFields}
      />
    </div>
  );
}
