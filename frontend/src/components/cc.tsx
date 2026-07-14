"use client";

/**
 * Command Center shared UI primitives (M18).
 *
 * Premium dark cyber-defense visual language, reusing the existing
 * RedForge Tailwind palette (gray-950/900/800 surfaces, red-500 accent).
 * All charts are bundled inline SVG (the app has no chart library and a
 * strict CSP forbids CDNs). Honest states are first-class: loading,
 * error, permission-denied, empty, and not-configured each have a
 * dedicated primitive so no panel ever silently fabricates content.
 */

import { useCallback, useEffect, useState } from "react";
import { ApiError } from "@/lib/api";

// ── Async data hook with explicit permission/error/empty states ──────────────

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  forbidden: boolean;
  reload: () => void;
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setForbidden(false);
    fn()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
          setForbidden(true);
        } else {
          setError(e instanceof Error ? e.message : "Request failed");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  return { data, loading, error, forbidden, reload };
}

// ── Layout primitives ────────────────────────────────────────────────────────

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-gray-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  right,
  children,
  className = "",
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-gray-800 bg-gray-900/60 ${className}`}
    >
      {title && (
        <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
            {title}
          </h2>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function KpiTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "default" | "danger" | "warning" | "ok";
}) {
  const toneClass =
    tone === "danger"
      ? "text-red-400"
      : tone === "warning"
        ? "text-amber-400"
        : tone === "ok"
          ? "text-emerald-400"
          : "text-gray-100";
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-4">
      <div className="text-xs font-medium uppercase tracking-wider text-gray-500">
        {label}
      </div>
      <div className={`mt-2 text-3xl font-bold tabular-nums ${toneClass}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-gray-500">{hint}</div>}
    </div>
  );
}

// ── State panels ─────────────────────────────────────────────────────────────

export function LoadingRow({ label = "Loading…" }: { label?: string }) {
  return <div className="py-6 text-center text-sm text-gray-500">{label}</div>;
}

export function ErrorRow({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
      {message}
    </div>
  );
}

export function ForbiddenRow() {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-6 text-center text-sm text-gray-400">
      You don&apos;t have permission to view this. Access is enforced by the backend;
      ask an organization administrator to grant the required permission.
    </div>
  );
}

export function EmptyRow({ label = "No data yet." }: { label?: string }) {
  return <div className="py-6 text-center text-sm text-gray-500">{label}</div>;
}

/** Honest not-configured state for an external-telemetry integration. */
export function NotConfigured({ label, detail }: { label: string; detail?: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-700 bg-gray-900/40 px-4 py-8 text-center">
      <div className="text-xs font-semibold uppercase tracking-widest text-gray-500">
        Not Configured
      </div>
      <div className="mt-2 text-sm text-gray-400">{label}</div>
      {detail && <div className="mt-1 text-xs text-gray-600">{detail}</div>}
      <div className="mt-3 text-[11px] text-gray-600">
        No telemetry provider is wired. No values are shown because none exist.
      </div>
    </div>
  );
}

/** Wrap async content: renders the right state, else the children with data. */
export function AsyncContent<T>({
  state,
  children,
  empty,
  emptyLabel,
}: {
  state: AsyncState<T>;
  children: (data: T) => React.ReactNode;
  empty?: (data: T) => boolean;
  emptyLabel?: string;
}) {
  if (state.loading) return <LoadingRow />;
  if (state.forbidden) return <ForbiddenRow />;
  if (state.error) return <ErrorRow message={state.error} />;
  if (state.data === null) return <EmptyRow label={emptyLabel} />;
  if (empty && empty(state.data)) return <EmptyRow label={emptyLabel} />;
  return <>{children(state.data)}</>;
}

// ── Badges ───────────────────────────────────────────────────────────────────

const SEVERITY_TONE: Record<string, string> = {
  critical: "border-red-800 bg-red-950/60 text-red-300",
  high: "border-orange-800 bg-orange-950/50 text-orange-300",
  warning: "border-amber-800 bg-amber-950/50 text-amber-300",
  medium: "border-amber-800 bg-amber-950/50 text-amber-300",
  notice: "border-sky-800 bg-sky-950/50 text-sky-300",
  low: "border-sky-800 bg-sky-950/50 text-sky-300",
  info: "border-gray-700 bg-gray-800/60 text-gray-300",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = SEVERITY_TONE[severity.toLowerCase()] ?? SEVERITY_TONE.info;
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${tone}`}
    >
      {severity}
    </span>
  );
}

const STATUS_TONE: Record<string, string> = {
  not_configured: "border-gray-700 bg-gray-800/60 text-gray-400",
  awaiting_telemetry: "border-sky-800 bg-sky-950/50 text-sky-300",
  active: "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  error: "border-red-800 bg-red-950/60 text-red-300",
};

export function StatusPill({ status }: { status: string }) {
  const tone = STATUS_TONE[status.toLowerCase()] ?? STATUS_TONE.not_configured;
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${tone}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

// ── Inline SVG charts (CSP-safe, no external library) ────────────────────────

const BAND_COLOR: Record<string, string> = {
  strong: "#34d399",
  moderate: "#fbbf24",
  at_risk: "#fb923c",
  critical: "#f87171",
};

/** Posture score as a semicircular gauge — pure inline SVG. */
export function PostureGauge({ score, band }: { score: number; band: string }) {
  const clamped = Math.max(0, Math.min(100, score));
  const angle = Math.PI * (1 - clamped / 100); // 180deg (left) → 0deg (right)
  const cx = 100;
  const cy = 100;
  const r = 80;
  const x = cx + r * Math.cos(angle);
  const y = cy - r * Math.sin(angle);
  const color = BAND_COLOR[band] ?? "#9ca3af";
  return (
    <svg viewBox="0 0 200 120" className="w-full max-w-[240px]" role="img"
      aria-label={`Posture score ${clamped} of 100, band ${band}`}>
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#1f2937" strokeWidth="14"
        strokeLinecap="round" />
      <path
        d={`M20 100 A80 80 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}`}
        fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
      />
      <text x="100" y="92" textAnchor="middle" className="fill-gray-100"
        style={{ fontSize: 34, fontWeight: 700 }}>
        {clamped}
      </text>
      <text x="100" y="112" textAnchor="middle" className="fill-gray-500"
        style={{ fontSize: 11, letterSpacing: 1 }}>
        {band.replace(/_/g, " ").toUpperCase()}
      </text>
    </svg>
  );
}

/** Horizontal bar chart from label→count — pure inline SVG. */
export function MiniBars({
  data,
  colorFor,
}: {
  data: { label: string; value: number }[];
  colorFor?: (label: string) => string;
}) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="space-y-2">
      {data.map((d) => (
        <div key={d.label} className="flex items-center gap-2">
          <div className="w-28 shrink-0 truncate text-xs text-gray-400" title={d.label}>
            {d.label}
          </div>
          <div className="h-3 flex-1 overflow-hidden rounded bg-gray-800">
            <div
              className="h-full rounded"
              style={{
                width: `${(d.value / max) * 100}%`,
                backgroundColor: colorFor ? colorFor(d.label) : "#ef4444",
              }}
            />
          </div>
          <div className="w-10 shrink-0 text-right text-xs tabular-nums text-gray-300">
            {d.value}
          </div>
        </div>
      ))}
    </div>
  );
}

export function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ── Global Live Threat/Security Strip ───────────────────────────────────────

export interface StripMetric {
  label: string;
  value: number;
  tone?: "critical" | "high" | "warning" | "ok" | "neutral";
  href?: string;
}

const STRIP_TONE: Record<string, string> = {
  critical: "border-red-700 bg-red-950/70 text-red-300 shadow-[0_0_16px_-4px_rgba(248,113,113,0.5)]",
  high: "border-orange-700 bg-orange-950/60 text-orange-300",
  warning: "border-amber-700 bg-amber-950/50 text-amber-300",
  ok: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
  neutral: "border-gray-800 bg-gray-900/60 text-gray-200",
};

/** Persistent, severity-dominant strip. Values of 0 render calm; any
 * critical/high metric > 0 gets a glow + gentle pulse so it visually
 * dominates without imitating a game HUD. */
export function GlobalSecurityStrip({ metrics }: { metrics: StripMetric[] }) {
  return (
    <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
      {metrics.map((m) => {
        const tone = m.tone ?? "neutral";
        const dominant = (tone === "critical" || tone === "high") && m.value > 0;
        const inner = (
          <div
            className={`rounded-lg border px-3 py-2 transition-colors ${STRIP_TONE[tone]} ${
              dominant ? "animate-pulse" : ""
            }`}
          >
            <div className="text-[10px] font-semibold uppercase tracking-wider opacity-80">
              {m.label}
            </div>
            <div className="mt-0.5 text-xl font-bold tabular-nums">{m.value}</div>
          </div>
        );
        return m.href ? (
          <a key={m.label} href={m.href} className="block">
            {inner}
          </a>
        ) : (
          <div key={m.label}>{inner}</div>
        );
      })}
    </div>
  );
}

// ── Dense data console (table-like, high information density) ──────────────

export interface ConsoleColumn<T> {
  key: string;
  header: string;
  width?: string;
  render: (row: T) => React.ReactNode;
}

/** Dense, monospace-leaning console table for live/operational rows.
 * Deliberately compact rows (not a spacious CRUD table) — this is the
 * visual difference between a SOC console and an admin dashboard. */
export function DataConsole<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  emptyLabel = "No rows.",
}: {
  columns: ConsoleColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  emptyLabel?: string;
}) {
  if (rows.length === 0) return <EmptyRow label={emptyLabel} />;
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full min-w-[720px] border-collapse text-xs">
        <thead>
          <tr className="border-b border-gray-800 bg-gray-900/80">
            {columns.map((c) => (
              <th
                key={c.key}
                style={{ width: c.width }}
                className="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-gray-500"
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            const selected = key === selectedKey;
            return (
              <tr
                key={key}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={`border-b border-gray-900 ${
                  onRowClick ? "cursor-pointer hover:bg-gray-800/50" : ""
                } ${selected ? "bg-gray-800/70" : ""}`}
              >
                {columns.map((c) => (
                  <td key={c.key} className="px-2 py-1.5 align-top text-gray-300">
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Filter chips / search / pause-resume ────────────────────────────────────

export function FilterChip({
  label,
  active,
  onClick,
  tone = "neutral",
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  tone?: "neutral" | "critical" | "high" | "warning" | "ok";
}) {
  const activeTone = STRIP_TONE[tone] ?? STRIP_TONE.neutral;
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide transition-colors ${
        active ? activeTone : "border-gray-800 bg-gray-900/40 text-gray-500 hover:text-gray-300"
      }`}
    >
      {label}
    </button>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="rounded-md border border-gray-800 bg-gray-950/80 px-2.5 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-red-700 focus:outline-none"
    />
  );
}

export function PauseResumeButton({
  paused,
  onToggle,
}: {
  paused: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${
        paused
          ? "border-amber-700 bg-amber-950/40 text-amber-300"
          : "border-emerald-800 bg-emerald-950/30 text-emerald-300"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${paused ? "bg-amber-400" : "bg-emerald-400 animate-pulse"}`}
      />
      {paused ? "Paused" : "Live"}
    </button>
  );
}

// ── Investigation Drawer ─────────────────────────────────────────────────────

export interface DrawerField {
  label: string;
  value: React.ReactNode;
}

/** Reusable slide-in investigation panel for any selectable row: events,
 * conditions, drift signals, behavior signals, assets, ports/services,
 * relationships. Renders exactly the fields it is given — never invents
 * a field the caller didn't supply. */
export function InvestigationDrawer({
  open,
  onClose,
  title,
  subtitle,
  fields,
  links,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  fields: DrawerField[];
  links?: { label: string; href: string }[];
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative z-50 flex h-full w-full max-w-md flex-col overflow-y-auto border-l border-gray-800 bg-gray-950 shadow-2xl">
        <div className="flex items-start justify-between border-b border-gray-800 px-5 py-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
            {subtitle && <p className="mt-0.5 text-xs text-gray-500">{subtitle}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-gray-800 px-2 py-1 text-xs text-gray-400 hover:text-gray-200"
          >
            Close
          </button>
        </div>
        <div className="flex-1 space-y-3 px-5 py-4">
          {fields.map((f, i) => (
            <div key={i} className="border-b border-gray-900 pb-2">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                {f.label}
              </div>
              <div className="mt-0.5 break-words text-sm text-gray-200">{f.value}</div>
            </div>
          ))}
        </div>
        {links && links.length > 0 && (
          <div className="border-t border-gray-800 px-5 py-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              Drill down
            </div>
            <div className="flex flex-wrap gap-2">
              {links.map((l) => (
                <a
                  key={l.href}
                  href={l.href}
                  className="rounded-md border border-gray-800 bg-gray-900/60 px-2.5 py-1 text-xs text-red-300 hover:border-red-800 hover:bg-red-950/40"
                >
                  {l.label}
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
