/**
 * Design tokens for the platform realization phase.
 *
 * PLATFORM-WIDE CONSISTENCY AUDIT (this pass): this file and
 * `src/components/cc.tsx` (the pre-existing shared primitive library
 * used by 43 of 45 app pages — confirmed by grep — versus this
 * design-system's 2: `dashboard` and `executive`) had drifted into
 * two different visual languages for the exact same concepts:
 * medium/low severity rendered as yellow/blue here but amber/sky in
 * `cc.tsx`; severity badges had no border here but a bordered pill in
 * `cc.tsx`; cards were opaque `bg-gray-900` here but translucent
 * `bg-gray-900/60` in `cc.tsx`'s `Panel`; page titles used
 * `text-white`/no `tracking-tight` here vs `text-gray-100`/
 * `tracking-tight` in `cc.tsx`'s `PageHeader`. Since `cc.tsx` is the
 * dominant, already-shipped standard across the platform, these
 * tokens are now normalized to match it exactly, rather than the
 * other way around — the 2 outlier pages converge on the standard 43
 * pages already established, not vice versa. No visual behavior was
 * invented; every value below is copied from `cc.tsx`'s own
 * `SEVERITY_TONE`/`STATUS_TONE`/`Panel`/`PageHeader` constants.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type StatusTone = "success" | "warning" | "danger" | "neutral" | "info";

/** Severity -> Tailwind class pairs — byte-identical to `cc.tsx`'s `SEVERITY_TONE`. */
export const SEVERITY_BADGE_CLASSES: Record<Severity, string> = {
  critical: "border-red-800 bg-red-950/60 text-red-300",
  high: "border-orange-800 bg-orange-950/50 text-orange-300",
  medium: "border-amber-800 bg-amber-950/50 text-amber-300",
  low: "border-sky-800 bg-sky-950/50 text-sky-300",
  informational: "border-gray-700 bg-gray-800/60 text-gray-300",
};

/** Severity -> border/text pair for KPI card accents — same hue family as `SEVERITY_BADGE_CLASSES`. */
export const SEVERITY_ACCENT_CLASSES: Record<Severity, string> = {
  critical: "border-red-800 text-red-400",
  high: "border-orange-800 text-orange-400",
  medium: "border-amber-800 text-amber-400",
  low: "border-sky-800 text-sky-400",
  informational: "border-gray-700 text-gray-400",
};

/** Hex equivalents of the same severity palette, for ECharts/MapLibre
 * (which take raw color strings, not Tailwind classes). Sampled from
 * the same red/orange/amber/sky/gray-400 swatches `cc.tsx` uses, so
 * chart colors visually match badge colors platform-wide. */
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  informational: "#9ca3af",
};

/** Matches `cc.tsx`'s `active`/`error`/`awaiting_telemetry`/`not_configured`
 * hue families (emerald/red/sky/gray) extended to the broader
 * success/warning/danger/neutral/info vocabulary this design system uses. */
export const STATUS_TONE_CLASSES: Record<StatusTone, string> = {
  success: "text-emerald-400",
  warning: "text-amber-400",
  danger: "text-red-400",
  neutral: "text-gray-500",
  info: "text-sky-400",
};

export const STATUS_TONE_HEX: Record<StatusTone, string> = {
  success: "#34d399",
  warning: "#fbbf24",
  danger: "#f87171",
  neutral: "#6b7280",
  info: "#38bdf8",
};

/** Maps a free-text platform status string (as returned by health/readiness/
 * target/etc. endpoints, which have no closed enum today) to a StatusTone.
 * Preserves the existing dashboard's `healthy|ok|ready -> green` rule as the
 * single canonical place this logic lives, instead of every page re-deriving it. */
export function statusToTone(status: string): StatusTone {
  const normalized = status.toLowerCase();
  if (["healthy", "ok", "ready", "active", "enabled", "resolved", "completed"].includes(normalized)) {
    return "success";
  }
  if (["degraded", "warning", "pending", "paused"].includes(normalized)) {
    return "warning";
  }
  if (["unhealthy", "failed", "error", "critical", "blocked", "disabled"].includes(normalized)) {
    return "danger";
  }
  return "neutral";
}

/** Card surface — byte-identical to `cc.tsx`'s `Panel` surface
 * (`rounded-xl border border-gray-800 bg-gray-900/60`), translucent
 * rather than opaque, matching the dominant standard. */
export const CARD_CLASSES = "rounded-xl border border-gray-800 bg-gray-900/60";
export const CARD_PADDING = "p-4";

/** Section header — byte-identical to `cc.tsx`'s `Panel` title bar text style. */
export const SECTION_HEADER_CLASSES = "text-xs font-semibold uppercase tracking-wider text-gray-400";

/** Page-level title/subtitle — byte-identical to `cc.tsx`'s `PageHeader`. */
export const PAGE_TITLE_CLASSES = "text-2xl font-bold tracking-tight text-gray-100";
export const PAGE_SUBTITLE_CLASSES = "mt-1 text-sm text-gray-500";

/** Spacing scale used for stacking dashboard sections — matches the
 * `mt-4` / `mt-6` / `mt-8` rhythm already used in `dashboard/page.tsx`. */
export const SPACING = {
  section: "mt-8",
  block: "mt-6",
  tight: "mt-4",
} as const;

/** Shared dark theme applied to ECharts instances so every chart widget
 * looks consistent with the app's existing dark surface (gray-900 cards,
 * gray-400/gray-500 muted text) instead of ECharts' default light theme. */
export const ECHARTS_DARK_THEME = {
  backgroundColor: "transparent",
  textStyle: { color: "#d1d5db" },
  axisLine: { lineStyle: { color: "#374151" } },
  splitLine: { lineStyle: { color: "#1f2937" } },
} as const;
