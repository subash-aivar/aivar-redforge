"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { NAV_GROUPS } from "@/components/navigation/navConfig";

/** Finds the real nav group + item for the current pathname — the
 * breadcrumb is derived from the same single source of truth the
 * sidebar renders from, never a hand-maintained second copy. */
function resolveBreadcrumb(pathname: string): { groupTitle: string; itemLabel: string } | null {
  for (const group of NAV_GROUPS) {
    for (const item of group.items) {
      if (pathname === item.href || pathname.startsWith(item.href + "/")) {
        return { groupTitle: group.title, itemLabel: item.label };
      }
    }
  }
  return null;
}

export function Breadcrumb({ pathname }: { pathname: string }) {
  const resolved = resolveBreadcrumb(pathname);
  if (!resolved) return null;

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-gray-500">
      <Link href="/dashboard" className="hover:text-gray-300">
        RedForge
      </Link>
      <ChevronRight className="h-3 w-3" aria-hidden="true" />
      <span>{resolved.groupTitle}</span>
      <ChevronRight className="h-3 w-3" aria-hidden="true" />
      <span className="text-gray-300">{resolved.itemLabel}</span>
    </nav>
  );
}
