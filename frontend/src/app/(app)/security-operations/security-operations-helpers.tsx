/**
 * Pure presentation helpers for the Security Operations Command
 * Center — mirrors continuous-validation-helpers.tsx's conventions
 * exactly: closed const arrays, toCanonicalX() never guesses (falls
 * back to UNKNOWN), badge classes vs. dropdown labels kept separate.
 */

export function displayEnum(value: string | null | undefined): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

export const SOURCE_DOMAINS = [
  "authorization",
  "validation",
  "continuous_validation",
  "security_drift",
  "security_condition",
  "security_correlation",
  "runtime",
] as const;

export function toCanonicalSourceDomain(value: string | null | undefined): string {
  const lower = (value ?? "").toLowerCase();
  return (SOURCE_DOMAINS as readonly string[]).includes(lower) ? lower : "UNKNOWN";
}

const SOURCE_DOMAIN_LABELS: Record<string, string> = {
  authorization: "Authorization",
  validation: "Validation",
  continuous_validation: "Continuous Validation",
  security_drift: "Security Drift",
  security_condition: "Security Condition",
  security_correlation: "Security Correlation",
  runtime: "Runtime",
};

export function sourceDomainLabel(value: string | null | undefined): string {
  return SOURCE_DOMAIN_LABELS[toCanonicalSourceDomain(value)] ?? "Unknown";
}

export const OPERATIONAL_IMPORTANCES = ["info", "notice", "warning", "high", "critical"] as const;

export function toCanonicalImportance(value: string | null | undefined): string {
  const lower = (value ?? "").toLowerCase();
  return (OPERATIONAL_IMPORTANCES as readonly string[]).includes(lower) ? lower : "UNKNOWN";
}

const IMPORTANCE_COLORS: Record<string, string> = {
  info: "border-gray-700 bg-gray-800 text-gray-400",
  notice: "border-blue-800 bg-blue-950 text-blue-400",
  warning: "border-amber-800 bg-amber-950 text-amber-400",
  high: "border-orange-800 bg-orange-950 text-orange-400",
  critical: "border-red-800 bg-red-950 text-red-400",
  UNKNOWN: "border-gray-700 bg-gray-800 text-gray-500",
};

export function importanceBadgeClass(value: string | null | undefined): string {
  return IMPORTANCE_COLORS[toCanonicalImportance(value)] ?? IMPORTANCE_COLORS.UNKNOWN;
}

export const BOUNDED_PERIODS = ["1h", "24h", "7d", "30d"] as const;

const PERIOD_LABELS: Record<string, string> = {
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
};

export function periodLabel(value: string): string {
  return PERIOD_LABELS[value] ?? displayEnum(value);
}

export const RUNTIME_STATUSES = ["healthy", "degraded", "unhealthy", "unknown"] as const;

const RUNTIME_STATUS_COLORS: Record<string, string> = {
  healthy: "border-emerald-800 bg-emerald-950 text-emerald-400",
  degraded: "border-amber-800 bg-amber-950 text-amber-400",
  unhealthy: "border-red-800 bg-red-950 text-red-400",
  unknown: "border-gray-700 bg-gray-800 text-gray-500",
};

export function runtimeStatusBadgeClass(value: string | null | undefined): string {
  const lower = (value ?? "").toLowerCase();
  return RUNTIME_STATUS_COLORS[lower] ?? RUNTIME_STATUS_COLORS.unknown;
}

export const EXECUTION_PHASES = [
  "authorization",
  "resolution",
  "discovery",
  "service_validation",
  "adaptive_validation",
  "protocol_validation",
  "condition_processing",
  "correlation",
  "snapshot",
  "drift",
  "completed",
] as const;

const PHASE_LABELS: Record<string, string> = {
  authorization: "Authorization",
  resolution: "Resolution",
  discovery: "Discovery",
  service_validation: "Service Validation",
  adaptive_validation: "Adaptive Validation",
  protocol_validation: "Protocol Validation",
  condition_processing: "Condition Processing",
  correlation: "Correlation",
  snapshot: "Snapshot",
  drift: "Drift",
  completed: "Completed",
};

export function phaseLabel(value: string | null | undefined): string {
  const lower = (value ?? "").toLowerCase();
  return PHASE_LABELS[lower] ?? "Unknown";
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

export function formatEventTypeTitle(eventType: string): string {
  return eventType
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
