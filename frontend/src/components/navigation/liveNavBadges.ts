/**
 * Live navigation badges — real data only.
 *
 * Source: the shared M15 Security Operations event bus
 * (`EventBusProvider`/`usePlatformEventBus`), which every other live
 * widget in this app already consumes. No new endpoint, no new
 * connection.
 *
 * Each real `SourceDomain` (redforge.domain.security_operations
 * .value_objects.SourceDomain) is mapped to the ONE nav item that is
 * that bounded context's actual operational landing page — verified
 * against `navConfig.ts` before writing this map. A badge counts
 * critical/high-importance events seen on the live connection so far
 * this session (bounded by the stream's own 200-event rolling buffer)
 * — it is explicitly a live rolling count, not a historical/DB total,
 * since no such aggregate endpoint is being invented here.
 *
 * `security_drift`, `security_condition`, `security_correlation`,
 * `authorization`'s counterpart items, and `unknown` are NOT mapped:
 * no nav item exists today that is unambiguously "the" landing page
 * for those specific domains (as opposed to a shared cross-domain
 * view like Command Center Overview). Rather than force a guess, they
 * are left unbadged — the owning bounded context still exists and
 * still publishes real events, they simply have no dedicated nav
 * destination to attach a per-item badge to yet.
 */
import type { OperationalEvent, SourceDomain } from "@/lib/securityOperations";

export const DOMAIN_TO_NAV_HREF: Partial<Record<SourceDomain, string>> = {
  ddos: "/ddos",
  behavior: "/behavior",
  investigation: "/investigations",
  network_security: "/network-security",
  validation: "/validation-operations",
  continuous_validation: "/continuous-validation",
  authorization: "/authorization",
};

const NOTABLE_IMPORTANCE = new Set(["critical", "high"]);

/** href -> count of critical/high events seen on the live connection so far. */
export function computeLiveNavBadges(events: OperationalEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (!NOTABLE_IMPORTANCE.has(event.importance)) continue;
    const href = DOMAIN_TO_NAV_HREF[event.source_domain];
    if (!href) continue;
    counts[href] = (counts[href] ?? 0) + 1;
  }
  return counts;
}
