"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS: { href: string; label: string }[] = [
  { href: "/compliance", label: "Overview" },
  { href: "/compliance/frameworks", label: "Frameworks" },
  { href: "/compliance/assessments", label: "Assessments" },
  { href: "/compliance/recommendations", label: "Recommendations" },
  { href: "/compliance/evidence", label: "Evidence" },
  { href: "/compliance/timeline", label: "Timeline" },
  { href: "/compliance/analytics", label: "Analytics" },
];

export default function ComplianceLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <div className="min-h-full">
      <nav
        aria-label="Compliance console sections"
        className="mb-6 flex flex-wrap gap-1 border-b border-gray-800 pb-2"
      >
        {TABS.map((tab) => {
          const active =
            tab.href === "/compliance"
              ? pathname === "/compliance"
              : pathname === tab.href || pathname.startsWith(tab.href + "/");
          return (
            <Link
              key={tab.href}
              href={tab.href}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600 ${
                active
                  ? "bg-red-950/50 text-red-300"
                  : "text-gray-500 hover:bg-gray-900 hover:text-gray-200"
              }`}
            >
              {tab.label}
            </Link>
          );
        })}
      </nav>
      {children}
    </div>
  );
}
