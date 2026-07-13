/**
 * Pure presentation helpers for the Continuous Validation page —
 * mirrors validation-operations-helpers.tsx's conventions exactly.
 */

export const POLICY_LIFECYCLES = ["draft", "active", "paused", "disabled"] as const;

const LIFECYCLE_COLORS: Record<string, string> = {
  draft: "bg-gray-800 text-gray-400 border-gray-700",
  active: "bg-emerald-950 text-emerald-400 border-emerald-800",
  paused: "bg-amber-950 text-amber-400 border-amber-800",
  disabled: "bg-red-950 text-red-400 border-red-800",
  UNKNOWN: "bg-gray-800 text-gray-500 border-gray-700",
};

export function displayEnum(value: string | null | undefined): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

/** Never silently maps an unrecognized backend lifecycle to a known
 * one — a value this build doesn't recognize canonicalizes to
 * "UNKNOWN" rather than a misleading guess (mirrors
 * validation-operations-helpers.tsx's toCanonicalStatus()). */
export function toCanonicalLifecycle(lifecycle: string | null | undefined): string {
  const lower = (lifecycle ?? "").toLowerCase();
  return (POLICY_LIFECYCLES as readonly string[]).includes(lower) ? lower : "UNKNOWN";
}

export function lifecycleBadgeClass(lifecycle: string | null | undefined): string {
  return LIFECYCLE_COLORS[toCanonicalLifecycle(lifecycle)] ?? LIFECYCLE_COLORS.UNKNOWN;
}

export function lifecycleLabel(lifecycle: string | null | undefined): string {
  const labels: Record<string, string> = {
    draft: "Draft",
    active: "Active",
    paused: "Paused",
    disabled: "Disabled",
  };
  return labels[toCanonicalLifecycle(lifecycle)] ?? "UNKNOWN";
}

/** Closed, server-controlled cadence registry. No free-text cron
 * expression anywhere in this client — see api/v1/continuous_validation.py's
 * own module docstring for the same discipline on the backend. */
export const VALIDATION_CADENCES = ["hourly", "every_6_hours", "daily", "weekly"] as const;

const CADENCE_LABELS: Record<string, string> = {
  hourly: "Hourly",
  every_6_hours: "Every 6 Hours",
  daily: "Daily",
  weekly: "Weekly",
};

export function cadenceLabel(cadence: string): string {
  return CADENCE_LABELS[cadence] ?? displayEnum(cadence);
}

export const VALIDATION_PROFILES = [
  "safe_active_baseline_v1",
  "network_discovery_baseline_v1",
] as const;

/** Closed SecurityDriftCategory taxonomy — crisp, non-story-prose
 * operator language. Never a fabricated distinction beyond what the
 * backend can actually prove (see domain/continuous_validation/
 * value_objects.py's own docstring for why CORRELATION_REACTIVATED is
 * absent). */
const DRIFT_CATEGORY_LABELS: Record<string, string> = {
  ip_observed: "IP Observed",
  ip_no_longer_observed: "IP No Longer Observed",
  port_became_reachable: "Port Became Reachable",
  port_no_longer_reachable: "Port No Longer Reachable",
  protocol_validated: "Protocol Validated",
  protocol_no_longer_validated: "Protocol No Longer Validated",
  protocol_changed: "Protocol Changed",
  tls_certificate_changed: "TLS Certificate Changed",
  condition_appeared: "Condition Appeared",
  condition_resolved: "Condition Resolved",
  condition_reactivated: "Condition Reactivated",
  correlation_appeared: "Correlation Appeared",
  correlation_resolved: "Correlation Resolved",
};

export function driftCategoryLabel(category: string): string {
  return DRIFT_CATEGORY_LABELS[category] ?? displayEnum(category);
}

const DRIFT_CATEGORY_COLORS: Record<string, string> = {
  ip_observed: "border-blue-800 bg-blue-950 text-blue-400",
  port_became_reachable: "border-blue-800 bg-blue-950 text-blue-400",
  protocol_validated: "border-blue-800 bg-blue-950 text-blue-400",
  ip_no_longer_observed: "border-gray-700 bg-gray-800 text-gray-400",
  port_no_longer_reachable: "border-gray-700 bg-gray-800 text-gray-400",
  protocol_no_longer_validated: "border-gray-700 bg-gray-800 text-gray-400",
  protocol_changed: "border-amber-800 bg-amber-950 text-amber-400",
  tls_certificate_changed: "border-amber-800 bg-amber-950 text-amber-400",
  condition_appeared: "border-red-800 bg-red-950 text-red-400",
  condition_reactivated: "border-red-800 bg-red-950 text-red-400",
  correlation_appeared: "border-red-800 bg-red-950 text-red-400",
  condition_resolved: "border-emerald-800 bg-emerald-950 text-emerald-400",
  correlation_resolved: "border-emerald-800 bg-emerald-950 text-emerald-400",
};

export function driftCategoryBadgeClass(category: string): string {
  return DRIFT_CATEGORY_COLORS[category] ?? "border-gray-700 bg-gray-800 text-gray-500";
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}
