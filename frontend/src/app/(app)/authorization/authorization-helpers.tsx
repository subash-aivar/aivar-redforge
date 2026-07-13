/**
 * Pure presentation helpers for the Authorization & Execution Policy
 * page — extracted from page.tsx so they're unit-testable without
 * rendering the whole page, mirroring campaigns/campaign-graph.tsx.
 */

export const CANONICAL_STATUSES = [
  "draft",
  "pending_approval",
  "active",
  "rejected",
  "revoked",
  "expired",
] as const;

const STATUS_COLORS: Record<string, string> = {
  draft: "bg-gray-800 text-gray-400 border-gray-700",
  pending_approval: "bg-amber-950 text-amber-400 border-amber-800",
  active: "bg-emerald-950 text-emerald-400 border-emerald-800",
  rejected: "bg-red-950 text-red-400 border-red-800",
  revoked: "bg-red-950 text-red-400 border-red-800",
  expired: "bg-gray-800 text-gray-500 border-gray-700",
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

/** Action classes a client is permitted to request. EXPLOIT_EXECUTION,
 * POST_EXPLOITATION, and DESTRUCTIVE_ACTION are deliberately absent —
 * the backend rejects them outright (no execution capability exists
 * for them), so the create form never offers them as options. */
export const REQUESTABLE_ACTION_CLASSES = [
  "passive_discovery",
  "read_only_assessment",
  "safe_validation",
  "active_validation",
  "credential_validation",
] as const;

export const SCOPE_ENTITY_TYPES = ["ai_target", "ai_asset"] as const;

const DECISION_COLORS: Record<string, string> = {
  allow: "bg-emerald-950 text-emerald-400 border-emerald-800",
  deny: "bg-red-950 text-red-400 border-red-800",
  approval_required: "bg-amber-950 text-amber-400 border-amber-800",
  UNKNOWN: "bg-gray-800 text-gray-500 border-gray-700",
};

export function decisionBadgeClass(rawDecision: string | null | undefined): string {
  const lower = (rawDecision ?? "").toLowerCase();
  return DECISION_COLORS[lower] ?? DECISION_COLORS.UNKNOWN;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}
