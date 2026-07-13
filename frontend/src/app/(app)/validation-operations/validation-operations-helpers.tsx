/**
 * Pure presentation helpers for the Validation Operations page —
 * extracted from page.tsx so they're unit-testable without rendering
 * the whole page, mirroring authorization/authorization-helpers.tsx.
 */

export const CANONICAL_STATUSES = [
  "pending",
  "policy_checking",
  "authorized",
  "running",
  "completed",
  "partially_completed",
  "failed",
  "cancelled",
  "denied",
] as const;

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-gray-800 text-gray-400 border-gray-700",
  policy_checking: "bg-amber-950 text-amber-400 border-amber-800",
  authorized: "bg-blue-950 text-blue-400 border-blue-800",
  running: "bg-blue-950 text-blue-400 border-blue-800",
  completed: "bg-emerald-950 text-emerald-400 border-emerald-800",
  partially_completed: "bg-amber-950 text-amber-400 border-amber-800",
  failed: "bg-red-950 text-red-400 border-red-800",
  cancelled: "bg-gray-800 text-gray-500 border-gray-700",
  denied: "bg-red-950 text-red-400 border-red-800",
  UNKNOWN: "bg-gray-800 text-gray-500 border-gray-700",
};

/** Never silently maps an unrecognized backend status to a known one —
 * an enum value this build doesn't recognize renders as UNKNOWN rather
 * than a misleading guess. */
export function toCanonicalStatus(rawStatus: string | null | undefined): string {
  const lower = (rawStatus ?? "").toLowerCase();
  return (CANONICAL_STATUSES as readonly string[]).includes(lower) ? lower : "UNKNOWN";
}

export function statusBadgeClass(rawStatus: string | null | undefined): string {
  const canonical = toCanonicalStatus(rawStatus);
  return STATUS_COLORS[canonical] ?? STATUS_COLORS.UNKNOWN;
}

export function displayEnum(value: string | null | undefined): string {
  if (!value) return "UNKNOWN";
  return value.toUpperCase();
}

const STEP_STATUS_COLORS: Record<string, string> = {
  pending: "bg-gray-800 text-gray-400 border-gray-700",
  running: "bg-blue-950 text-blue-400 border-blue-800",
  completed: "bg-emerald-950 text-emerald-400 border-emerald-800",
  failed: "bg-red-950 text-red-400 border-red-800",
  skipped: "bg-gray-800 text-gray-500 border-gray-700",
  timed_out: "bg-red-950 text-red-400 border-red-800",
  cancelled: "bg-gray-800 text-gray-500 border-gray-700",
  UNKNOWN: "bg-gray-800 text-gray-500 border-gray-700",
};

export function stepStatusBadgeClass(rawStatus: string | null | undefined): string {
  const lower = (rawStatus ?? "").toLowerCase();
  return STEP_STATUS_COLORS[lower] ?? STEP_STATUS_COLORS.UNKNOWN;
}

/** The two closed, server-controlled validation profiles. There is
 * deliberately no other option — the client can never request an
 * arbitrary step, port, module, or scan command. */
export const VALIDATION_PROFILES = [
  "safe_active_baseline_v1",
  "network_discovery_baseline_v1",
] as const;

const STEP_TYPE_LABELS: Record<string, string> = {
  dns_resolution: "DNS Resolution",
  tcp_connectivity: "TCP Connectivity",
  tls_handshake: "TLS Handshake",
  http_metadata: "HTTP Metadata",
  http_security_headers: "HTTP Security Headers",
  service_reachability: "Service Reachability",
  port_discovery: "Port Discovery",
  ssh_banner: "SSH Banner",
  mysql_handshake: "MySQL Handshake",
  postgresql_handshake: "PostgreSQL Handshake",
  redis_ping: "Redis Ping",
};

export function stepTypeLabel(stepType: string): string {
  return STEP_TYPE_LABELS[stepType] ?? displayEnum(stepType);
}

const EVENT_TYPE_LABELS: Record<string, string> = {
  execution_created: "Execution Created",
  policy_check_started: "Policy Check Started",
  policy_allowed: "Policy Allowed",
  policy_denied: "Policy Denied",
  plan_created: "Plan Created",
  step_started: "Step Started",
  step_completed: "Step Completed",
  step_failed: "Step Failed",
  condition_ingested: "Condition Ingested",
  execution_completed: "Execution Completed",
  execution_partial: "Execution Partially Completed",
  execution_failed: "Execution Failed",
  execution_cancelled: "Execution Cancelled",
  discovery_started: "Discovery Started",
  port_reachability_observed: "Port Reachability Observed",
  adaptive_rule_matched: "Adaptive Rule Matched",
  step_added_to_plan: "Step Added To Plan",
  asset_resolved: "Asset Resolved",
  service_context_updated: "Service Context Updated",
  correlation_evaluated: "Correlation Evaluated",
};

export function eventTypeLabel(eventType: string): string {
  return EVENT_TYPE_LABELS[eventType] ?? displayEnum(eventType);
}

const SOURCE_LABELS: Record<string, string> = {
  initial: "Initial",
  adaptive: "Adaptive",
};

export function stepSourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? displayEnum(source);
}

export function stepSourceBadgeClass(source: string): string {
  return source === "adaptive"
    ? "bg-purple-950 text-purple-400 border-purple-800"
    : "bg-gray-800 text-gray-400 border-gray-700";
}

const SERVICE_STATE_LABELS: Record<string, string> = {
  hinted: "Hinted",
  validated: "Validated",
};

export function serviceStateLabel(state: string): string {
  return SERVICE_STATE_LABELS[state] ?? displayEnum(state);
}

/** M13 — the explicit REACHABLE -> HINTED -> VALIDATED evidence ladder
 * for one protocol-validator step. Never render HINTED/INCONCLUSIVE as
 * VALIDATED — the whole point of this ladder is that a reachable port
 * alone is never service identity. */
const PROTOCOL_VALIDATION_STATE_LABELS: Record<string, string> = {
  not_attempted: "Not Attempted",
  unreachable: "Unreachable",
  inconclusive: "Inconclusive",
  hinted: "Hinted",
  validated: "Validated",
  error: "Error",
};

export function protocolValidationStateLabel(state: string | null | undefined): string {
  if (!state) return "—";
  return PROTOCOL_VALIDATION_STATE_LABELS[state] ?? displayEnum(state);
}

export function protocolValidationStateBadgeClass(state: string | null | undefined): string {
  switch (state) {
    case "validated":
      return "border-emerald-800 bg-emerald-950 text-emerald-400";
    case "hinted":
      return "border-gray-700 bg-gray-800 text-gray-400";
    case "inconclusive":
      return "border-amber-800 bg-amber-950 text-amber-400";
    case "error":
    case "unreachable":
      return "border-red-800 bg-red-950 text-red-400";
    default:
      return "border-gray-700 bg-gray-800 text-gray-500";
  }
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}
