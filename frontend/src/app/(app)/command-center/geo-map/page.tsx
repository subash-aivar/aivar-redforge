"use client";

import { useMemo } from "react";
import {
  listGeoActivity,
  type GeoActivityPoint,
} from "@/lib/telemetry";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  Panel,
  PageHeader,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import { useState } from "react";

// ── Mercator projection ────────────────────────────────────────────────────
// Maps (lon, lat) to SVG pixel coordinates for a 1000×500 canvas.
// This is a simplified equirectangular-ish projection sufficient for a
// global indicator scatter; it is NOT a navigational chart.
const MAP_W = 1000;
const MAP_H = 500;

function lonLatToXY(lon: number, lat: number): [number, number] {
  // Equirectangular: x proportional to longitude, y to latitude
  const x = ((lon + 180) / 360) * MAP_W;
  // Clamp lat to ±85 to avoid Mercator poles blow-up
  const clampedLat = Math.max(-85, Math.min(85, lat));
  const latRad = (clampedLat * Math.PI) / 180;
  // Simple Mercator y
  const mercY = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
  const maxMercY = Math.log(Math.tan(Math.PI / 4 + (85 * Math.PI) / 180));
  const y = MAP_H / 2 - (MAP_H / (2 * maxMercY)) * mercY;
  return [x, y];
}

// ── Enriched IP list columns ────────────────────────────────────────────────
const IP_COLUMNS: ConsoleColumn<GeoActivityPoint>[] = [
  {
    key: "ip",
    header: "IP",
    width: "130px",
    render: (p) => <span className="font-mono text-gray-200">{p.ip}</span>,
  },
  {
    key: "country",
    header: "Country",
    width: "80px",
    render: (p) => <span className="text-gray-300">{p.country ?? "—"}</span>,
  },
  {
    key: "org",
    header: "Organization / Network",
    render: (p) => (
      <span className="text-gray-400">
        {p.organization ?? p.network_prefix ?? "—"}
      </span>
    ),
  },
  {
    key: "asn",
    header: "ASN",
    width: "100px",
    render: (p) => (
      <span className="font-mono text-[11px] text-gray-500">{p.asn ?? "—"}</span>
    ),
  },
  {
    key: "provider",
    header: "Provider",
    width: "120px",
    render: (p) => (
      <span className="text-[11px] text-gray-500">
        {p.geo_provider ?? p.asn_provider ?? "—"}
      </span>
    ),
  },
  {
    key: "coords",
    header: "Plottable",
    width: "80px",
    render: (p) => (
      <span className={p.latitude != null ? "text-sky-400" : "text-gray-700"}>
        {p.latitude != null ? "Yes" : "No coords"}
      </span>
    ),
  },
];

// ── Severity coloring based on reputation providers ────────────────────────
function pointColor(p: GeoActivityPoint): string {
  if (p.reputation_providers.length >= 3) return "#f87171"; // critical
  if (p.reputation_providers.length >= 1) return "#fb923c"; // flagged
  return "#38bdf8"; // seen, not flagged
}

function pointRadius(p: GeoActivityPoint): number {
  if (p.reputation_providers.length >= 3) return 5;
  if (p.reputation_providers.length >= 1) return 4;
  return 3;
}

// ── Simple world outline SVG paths (public domain simplified polygons) ─────
// A minimal world silhouette for orientation — these are approximate outlines
// only, not country boundaries. Source-coded, no external assets.
// 7 major land masses as rough closed paths in map-coordinate space.
const CONTINENTS = [
  // North America (approximate)
  "M 140,80 L 180,60 L 250,55 L 260,70 L 280,110 L 285,160 L 260,190 L 240,200 L 220,195 L 200,210 L 180,230 L 160,220 L 150,200 L 140,170 L 135,140 L 130,110 Z",
  // South America
  "M 200,230 L 220,225 L 245,240 L 260,270 L 270,320 L 265,370 L 245,400 L 220,410 L 200,400 L 185,370 L 180,320 L 188,270 L 195,245 Z",
  // Europe
  "M 460,60 L 500,50 L 540,55 L 560,70 L 555,90 L 530,100 L 510,110 L 490,120 L 470,115 L 455,100 L 448,80 Z",
  // Africa
  "M 460,120 L 510,110 L 560,115 L 580,140 L 590,180 L 585,230 L 570,270 L 550,310 L 520,340 L 490,345 L 465,330 L 448,290 L 440,240 L 442,190 L 450,150 Z",
  // Asia (rough)
  "M 540,55 L 660,45 L 780,50 L 820,75 L 810,120 L 770,140 L 740,160 L 700,155 L 660,165 L 620,170 L 590,165 L 565,145 L 555,120 L 545,90 Z",
  // Australia
  "M 740,280 L 800,265 L 840,275 L 860,300 L 855,330 L 830,355 L 790,360 L 755,345 L 735,315 L 733,290 Z",
  // Greenland
  "M 260,25 L 310,15 L 350,20 L 355,45 L 330,60 L 290,65 L 260,55 L 250,38 Z",
];

export default function GeoSecurityMapPage() {
  const geoData = useAsync(() => listGeoActivity(500), []);
  const [selected, setSelected] = useState<GeoActivityPoint | null>(null);

  const plotted = useMemo(() => {
    return (geoData.data ?? []).filter(
      (p) => p.latitude != null && p.longitude != null,
    );
  }, [geoData.data]);

  const drawerFields: DrawerField[] = selected
    ? [
        { label: "IP Address", value: <span className="font-mono">{selected.ip}</span> },
        { label: "Country", value: selected.country ?? "—" },
        { label: "Region", value: selected.region ?? "—" },
        { label: "City", value: selected.city ?? "—" },
        { label: "ASN", value: selected.asn ?? "—" },
        { label: "Network prefix", value: selected.network_prefix ?? "—" },
        { label: "Organization", value: selected.organization ?? "—" },
        { label: "RIR", value: selected.rir_source ?? "—" },
        {
          label: "Reputation flags",
          value:
            selected.reputation_providers.length > 0
              ? selected.reputation_providers.join(", ")
              : "None",
        },
        { label: "Geo provider", value: selected.geo_provider ?? "—" },
        { label: "ASN provider", value: selected.asn_provider ?? "—" },
        {
          label: "First seen",
          value: new Date(selected.first_seen_at).toLocaleString(),
        },
        {
          label: "Last seen",
          value: new Date(selected.last_seen_at).toLocaleString(),
        },
      ]
    : [];

  const totalPoints = geoData.data?.length ?? 0;
  const withCoords = plotted.length;
  const flagged = (geoData.data ?? []).filter(
    (p) => p.reputation_providers.length > 0,
  ).length;

  return (
    <div>
      <PageHeader
        title="Geo Security Activity Map"
        subtitle="Public IP indicators enriched with geolocation data. Approximate positions only — country attribution is based on registry/geo data and is NOT proof of attack origin. Private/internal IPs are excluded."
      />

      {/* KPI strip */}
      <div className="mb-4 grid grid-cols-3 gap-3 sm:grid-cols-3">
        {[
          { label: "Total enriched IPs", value: totalPoints },
          { label: "Plottable (lat/lon)", value: withCoords },
          { label: "Flagged by reputation", value: flagged },
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

      <Panel>
        <AsyncContent
          state={geoData}
          empty={(d) => d.length === 0}
          emptyLabel="No enriched IP indicators yet. Configure a threat intelligence provider to begin enrichment."
        >
          {() => (
            <div>
              {/* Legend */}
              <div className="mb-3 flex flex-wrap gap-4 text-[11px] text-gray-400">
                {[
                  { color: "#f87171", label: "3+ reputation flags" },
                  { color: "#fb923c", label: "1–2 reputation flags" },
                  { color: "#38bdf8", label: "Seen, not flagged" },
                ].map(({ color, label }) => (
                  <span key={label} className="flex items-center gap-1.5">
                    <span
                      className="inline-block h-2.5 w-2.5 rounded-full"
                      style={{ backgroundColor: color }}
                    />
                    {label}
                  </span>
                ))}
                <span className="ml-auto text-gray-600">
                  {withCoords} of {totalPoints} IPs plottable
                </span>
              </div>

              {/* Map canvas */}
              <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-950">
                <svg
                  viewBox={`0 0 ${MAP_W} ${MAP_H}`}
                  style={{ width: "100%", height: "auto", display: "block" }}
                  role="img"
                  aria-label="Geographic distribution of threat intelligence indicators"
                >
                  {/* Ocean background */}
                  <rect width={MAP_W} height={MAP_H} fill="#0f172a" />

                  {/* Continent silhouettes */}
                  {CONTINENTS.map((d, i) => (
                    <path
                      key={i}
                      d={d}
                      fill="#1e293b"
                      stroke="#334155"
                      strokeWidth={0.5}
                    />
                  ))}

                  {/* IP indicator dots */}
                  {plotted.map((p) => {
                    const [x, y] = lonLatToXY(p.longitude!, p.latitude!);
                    return (
                      <circle
                        key={p.ip}
                        cx={x}
                        cy={y}
                        r={pointRadius(p)}
                        fill={pointColor(p)}
                        fillOpacity={0.85}
                        stroke={
                          selected?.ip === p.ip ? "#fff" : "none"
                        }
                        strokeWidth={selected?.ip === p.ip ? 1.5 : 0}
                        style={{ cursor: "pointer" }}
                        onClick={() =>
                          setSelected(selected?.ip === p.ip ? null : p)
                        }
                      >
                        <title>
                          {p.ip}
                          {p.country ? ` · ${p.country}` : ""}
                          {p.reputation_providers.length > 0
                            ? ` · flagged by ${p.reputation_providers.join(", ")}`
                            : ""}
                        </title>
                      </circle>
                    );
                  })}
                </svg>
              </div>
              <p className="mt-2 text-[11px] text-gray-600">
                Click a dot to inspect the indicator. Geolocation is approximate
                — do not use country placement as evidence of attribution.
              </p>
            </div>
          )}
        </AsyncContent>
      </Panel>

      {/* Enriched IP list — all indicators, including those without coordinates */}
      {(geoData.data ?? []).length > 0 && (
        <Panel>
          <div className="mb-3 text-sm font-medium text-gray-300">
            Enriched IP Indicators
          </div>
          <DataConsole
            columns={IP_COLUMNS}
            rows={geoData.data ?? []}
            rowKey={(p) => p.ip}
            selectedKey={selected?.ip ?? null}
            onRowClick={(p) => setSelected(selected?.ip === p.ip ? null : p)}
          />
        </Panel>
      )}

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.ip ?? ""}
        subtitle={`Geo Security Map · ${selected?.country ?? "unknown country"}`}
        fields={drawerFields}
      />
    </div>
  );
}
