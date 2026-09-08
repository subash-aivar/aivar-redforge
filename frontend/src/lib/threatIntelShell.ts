/**
 * Shared registry for the M51 Native Threat Intelligence product shell
 * (Slice 1). One source of truth for the capability list so the shell
 * layout's sub-nav and the overview page never drift out of sync.
 *
 * `tenantReadPerm` values are the exact `Permission` enum strings from
 * `redforge.domain.identity.value_objects` (verified against backend
 * source, never guessed) — the same permission every M51 vertical's
 * live API already enforces server-side. This module never invents a
 * second authorization system: it only mirrors permission strings the
 * backend already defines, for UX-only show/hide decisions.
 */

export type ThreatIntelCapabilityStatus = "live" | "planned" | "disabled";

export interface ThreatIntelCapability {
  key: string;
  label: string;
  href: string;
  /** Tenant-scoped read permission that gates this capability's data. */
  tenantReadPerm: string;
  status: ThreatIntelCapabilityStatus;
  description: string;
}

export const THREAT_INTEL_OVERVIEW_HREF = "/threat-intelligence";

/** The nine certified M51 intelligence bounded contexts. IOC Intelligence
 * is the only one with a built operator UI so far (Slice 1 scope: shell
 * only, per M51 Slice 1 mission — the other eight get an honest
 * "not yet built" surface, never a fabricated one). */
export const THREAT_INTEL_CAPABILITIES: ThreatIntelCapability[] = [
  {
    key: "ioc",
    label: "IOC Intelligence",
    href: "/ioc-intelligence",
    tenantReadPerm: "ioc_intel:read",
    status: "live",
    description: "Indicators of compromise — provenance, evidence and lifecycle.",
  },
  {
    key: "threat-actors",
    label: "Threat Actors",
    href: "/threat-intelligence/threat-actors",
    tenantReadPerm: "threat_intel:read",
    status: "planned",
    description: "Attribution, motivation and sophistication of tracked adversaries.",
  },
  {
    key: "attack-patterns",
    label: "Attack Patterns",
    href: "/threat-intelligence/attack-patterns",
    tenantReadPerm: "attack_pattern_intel:read",
    status: "planned",
    description: "RedForge-native ATT&CK pattern intelligence and detection guidance.",
  },
  {
    key: "malware",
    label: "Malware",
    href: "/threat-intelligence/malware",
    tenantReadPerm: "malware_intel:read",
    status: "planned",
    description: "Malware families, capabilities and platform targeting.",
  },
  {
    key: "campaigns",
    label: "Campaigns",
    href: "/threat-intelligence/campaign-intel",
    tenantReadPerm: "campaign_intel:read",
    status: "planned",
    description: "Coordinated adversary activity across time and targets.",
  },
  {
    key: "tools",
    label: "Adversary Tools",
    href: "/threat-intelligence/tools",
    tenantReadPerm: "tool_intel:read",
    status: "planned",
    description: "Offensive tooling observed in use by tracked adversaries.",
  },
  {
    key: "infrastructure",
    label: "Infrastructure",
    href: "/threat-intelligence/infrastructure",
    tenantReadPerm: "infrastructure_intel:read",
    status: "planned",
    description: "Hosting, network and cloud infrastructure tied to adversary activity.",
  },
  {
    key: "threat-reports",
    label: "Threat Reports",
    href: "/threat-intelligence/threat-reports",
    tenantReadPerm: "threat_report_intel:read",
    status: "planned",
    description: "Catalogued third-party threat-intelligence publications.",
  },
  {
    key: "relationships",
    label: "Relationships",
    href: "/threat-intelligence/relationships",
    tenantReadPerm: "intelligence_relationships:read",
    status: "planned",
    description: "Typed, evidence-first edges between intelligence entities.",
  },
];

/** Not part of M51 — shown only as clearly disabled, no route, no click
 * target beyond a static explanation. Never gains a tenantReadPerm
 * because no backend capability exists yet to enforce one. */
export const THREAT_INTEL_FUTURE_SURFACES: { key: string; label: string; description: string }[] = [
  {
    key: "knowledge-graph",
    label: "Knowledge Graph",
    description: "Planned — traversal over certified intelligence entities. Not started.",
  },
  {
    key: "knowledge-quality",
    label: "Knowledge Quality",
    description: "Planned — confidence, freshness and provenance scoring. Not started.",
  },
];
