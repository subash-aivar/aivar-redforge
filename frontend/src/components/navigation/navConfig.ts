/**
 * Navigation configuration — extracted verbatim from the previous
 * `src/app/(app)/layout.tsx` (same groups, same items, same hrefs,
 * same icons, same `perm` gating requirements). No item was added,
 * removed, or re-permissioned as part of the navigation-framework
 * rebuild — this file is a lossless extraction, not a redesign of
 * what's in the nav, only of how it's presented.
 */

export interface NavItem {
  label: string;
  href: string;
  icon: string;
  perm?: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

/** Mirrors `redforge.core.config.ProductEdition` (ADR-0009) exactly —
 * the ONE edition concept, frontend side. */
export type ProductEdition = "full" | "network_defense";

/**
 * The ONE Network Defense Edition navigation allow-list (ADR-0009) —
 * mirrors the backend's tag-based `NETWORK_DEFENSE_TAGS`
 * (`redforge.api.v1.NETWORK_DEFENSE_TAGS`), using `href` as the
 * filtering key since nav items don't carry a router "tag". Every
 * entry here points at an EXISTING, already-working page — this list
 * adds no new pages and no new capability, only edition-scoped
 * visibility of what already exists (mission: "reuse existing working
 * pages", "missing future capabilities must not masquerade as working
 * product features" — there is deliberately no "Sensor Health" entry
 * anywhere in this file, because no such page exists yet).
 *
 * "full" edition applies no filter at all (mirrors the backend's
 * `allowed=None` for "full") — this set is only ever consulted for
 * "network_defense".
 */
export const NETWORK_DEFENSE_HREFS: ReadonlySet<string> = new Set([
  // Alerts (ADR-0006: the live SSE feed, not siem_alerting)
  "/security-operations",
  // Threat Intelligence (ADR-0007: M51 native suite shell)
  "/threat-intelligence",
  // Assets
  "/assets",
  // Network Overview
  "/network-security",
  "/connectors",
  // Network Behavior
  "/behavior",
  "/behavior/detections",
  "/behavior/entities",
  "/behavior/network",
  // DDoS + Traffic Analysis
  "/ddos",
  "/ddos/incidents",
  "/ddos/traffic",
  "/ddos/protected-resources",
  "/ddos/mitigation",
  // Investigations (ADR-0006: Family A, not incident/M34)
  "/investigations",
  // Response / Mitigation (governance + connector/credential surface)
  "/playbooks",
  "/automated-actions",
  "/integrations",
  "/credential-vault",
  // Operational / admin (shared core, required to operate the product)
  "/health",
  "/roles",
  "/groups-rbac",
  "/access-explorer",
]);

export function isNavItemVisibleInEdition(href: string, edition: ProductEdition): boolean {
  return edition === "full" || NETWORK_DEFENSE_HREFS.has(href);
}

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Command Center",
    items: [
      { label: "Overview", href: "/command-center", icon: "◎", perm: "security_operations:read" },
      { label: "Live Security", href: "/security-operations", icon: "⌘", perm: "security_operations:read" },
      { label: "Behavior Analytics", href: "/command-center/behavior", icon: "🧭", perm: "security_operations:read" },
      { label: "Threat Intelligence", href: "/threat-intelligence", icon: "🎯", perm: "ioc_intel:read" },
      { label: "TI Feed Enrichment", href: "/command-center/intelligence", icon: "🛡", perm: "security_operations:read" },
      { label: "Attack Paths", href: "/attack-paths", icon: "⇉", perm: "security_operations:read" },
      { label: "Findings", href: "/findings", icon: "⚠", perm: "findings:read" },
      { label: "Risk", href: "/risk", icon: "△" },
      { label: "Executive Posture", href: "/executive", icon: "◆" },
    ],
  },
  {
    title: "Assets & Network",
    items: [
      { label: "Asset Inventory", href: "/assets", icon: "▦" },
      { label: "Network Map", href: "/command-center/map", icon: "◈", perm: "security_operations:read" },
      { label: "Geo Security Map", href: "/command-center/geo-map", icon: "🌍", perm: "security_operations:read" },
      { label: "Firewall / IDS Wall", href: "/command-center/firewall", icon: "⛨", perm: "network_security:read" },
      { label: "Network Security", href: "/network-security", icon: "🛰", perm: "network_security:read" },
      { label: "Network Exposure", href: "/command-center/exposure", icon: "⌁", perm: "network_security:read" },
      { label: "DMZ & Zones", href: "/command-center/zones", icon: "▛", perm: "network_security:read" },
      { label: "Cloud Security", href: "/cloud-security", icon: "☁" },
      { label: "Connectors", href: "/connectors", icon: "⇄" },
      { label: "Targets", href: "/targets", icon: "⬡" },
    ],
  },
  {
    title: "Behavioral NDR",
    items: [
      { label: "NDR Operations Center", href: "/behavior", icon: "⬡", perm: "behavior:read" },
      { label: "Live Detections", href: "/behavior/detections", icon: "◈", perm: "behavior:read" },
      { label: "Entity Risk", href: "/behavior/entities", icon: "◉", perm: "behavior:read" },
      { label: "Network Graph", href: "/behavior/network", icon: "⬡", perm: "behavior:read" },
    ],
  },
  {
    title: "DDoS Defense",
    items: [
      { label: "DDoS Overview", href: "/ddos", icon: "⛨", perm: "ddos:read" },
      { label: "Active Incidents", href: "/ddos/incidents", icon: "⚡", perm: "ddos:read" },
      { label: "Traffic Analytics", href: "/ddos/traffic", icon: "〰", perm: "ddos:read" },
      { label: "Protected Resources", href: "/ddos/protected-resources", icon: "▣", perm: "ddos:manage" },
      { label: "Mitigation Center", href: "/ddos/mitigation", icon: "🛡", perm: "ddos:mitigation_approve" },
    ],
  },
  {
    title: "Investigation",
    items: [
      { label: "Investigations", href: "/investigations", icon: "⊕", perm: "investigations:read" },
      { label: "Incident Response", href: "/incident-response", icon: "🚨", perm: "incident:read" },
      { label: "Regulatory Notification", href: "/regulatory-notification", icon: "⚖" },
      { label: "Compliance", href: "/compliance", icon: "▣", perm: "compliance:read" },
    ],
  },
  {
    title: "Detection & Response",
    items: [
      { label: "Exposure Management", href: "/exposure-management", icon: "◉" },
      { label: "Exposure Intelligence", href: "/exposure", icon: "◎" },
      { label: "Exposure Reporting", href: "/exposure-reporting", icon: "📄" },
      { label: "Remediation Impact", href: "/remediation-impact", icon: "🛠" },
      { label: "Vulnerability", href: "/vulnerability", icon: "⊘" },
      { label: "Attack Surface", href: "/attack-surface", icon: "◆" },
      { label: "Attack Surface Assets", href: "/attack-surface/assets", icon: "▦" },
      { label: "Security Graph", href: "/security-graph", icon: "❖" },
      { label: "Attack Graph Explorer", href: "/attack-graph", icon: "🕸" },
      { label: "Identity Security", href: "/identity-security", icon: "⚑" },
      { label: "Identities", href: "/identities", icon: "☺" },
      { label: "Directory Groups", href: "/directory-groups", icon: "▤" },
      { label: "Campaigns", href: "/campaigns", icon: "⚔" },
      { label: "Validation Operations", href: "/validation-operations", icon: "✓" },
      { label: "Continuous Validation", href: "/continuous-validation", icon: "↻" },
      { label: "Authorization", href: "/authorization", icon: "🔒" },
      { label: "Threat Hunt", href: "/threat-hunt", icon: "🎯", perm: "threat_hunt:read" },
      { label: "Playbooks", href: "/playbooks", icon: "▶", perm: "playbooks:read" },
      { label: "Automated Actions", href: "/automated-actions", icon: "⚡", perm: "playbooks:read" },
      { label: "Lessons Learned", href: "/lessons-learned", icon: "📝", perm: "incident:read" },
    ],
  },
  {
    title: "Monitoring",
    items: [
      { label: "Integrations", href: "/command-center/integrations", icon: "🔌", perm: "security_operations:read" },
      { label: "Network Exposure (legacy)", href: "/network-exposure", icon: "⌗" },
      { label: "Runtime Health", href: "/health", icon: "♥" },
    ],
  },
  {
    title: "Analytics & AI Governance",
    items: [
      { label: "Analytics", href: "/analytics", icon: "📊", perm: "analytics:read" },
      { label: "Reporting", href: "/reporting", icon: "🗎" },
      { label: "Posture Forecasting", href: "/posture-forecasting", icon: "🔮" },
      { label: "ML Pipeline", href: "/ml-pipeline", icon: "🧠" },
      { label: "AI Posture", href: "/ai-posture", icon: "🤖", perm: "ai_posture:read" },
      { label: "AI Agent Governance", href: "/ai-governance", icon: "🛡", perm: "ai_posture:read" },
      { label: "AI Supply Chain", href: "/ai-supply-chain", icon: "🔗", perm: "ai_posture:read" },
      { label: "Integration Hub", href: "/integrations", icon: "🔌", perm: "integration_hub:read" },
    ],
  },
  {
    title: "Administration",
    items: [
      { label: "Roles & Permissions", href: "/roles", icon: "🛡", perm: "roles:read" },
      { label: "Groups", href: "/groups-rbac", icon: "◫", perm: "groups:read" },
      { label: "Access Explorer", href: "/access-explorer", icon: "🔍" },
      { label: "Credential Vault", href: "/credential-vault", icon: "🔐" },
    ],
  },
];

export function isItemActive(pathname: string, href: string): boolean {
  return (
    pathname === href ||
    (href !== "/command-center" && pathname.startsWith(href + "/")) ||
    (href === "/command-center" && pathname === "/command-center")
  );
}
