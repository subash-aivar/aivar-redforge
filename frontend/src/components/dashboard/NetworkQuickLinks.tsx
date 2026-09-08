import Link from "next/link";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";

const LINKS = [
  { href: "/ddos", label: "DDoS Defense", description: "Incidents & mitigation" },
  { href: "/network-security", label: "Network Security", description: "Inventory & monitoring" },
  { href: "/behavior", label: "Behavior Analytics", description: "NDR detections" },
  { href: "/threat-intelligence", label: "Threat Intelligence", description: "IOCs & feeds" },
  { href: "/investigations", label: "Investigations", description: "Cross-domain cases" },
  { href: "/assets", label: "Assets", description: "Asset inventory" },
] as const;

/** Quick-navigation panel for the Network Defense dashboard — every
 * destination is a real, already-mounted Network Defense route (see
 * `navConfig.ts`'s Network Defense nav groups). No destination here is
 * a Full-only page. */
export function NetworkQuickLinks() {
  return (
    <Card>
      <SectionHeader title="Go to" />
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
        {LINKS.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-lg border border-gray-800 bg-gray-950 p-3 transition hover:border-gray-700 hover:bg-gray-900"
          >
            <div className="text-sm font-medium text-gray-100">{link.label}</div>
            <div className="mt-1 text-xs text-gray-500">{link.description}</div>
          </Link>
        ))}
      </div>
    </Card>
  );
}
