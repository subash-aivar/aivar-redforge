"use client";

/**
 * Lightweight shared loaders for console surfaces that only need open periods
 * (e.g. generate recommendations). Does NOT load all assessments.
 */

import { useAsync } from "@/components/cc";
import { getConsoleOverview, type ConsoleOverview } from "@/lib/compliance";

export function useConsoleOverview() {
  return useAsync(() => getConsoleOverview(), []);
}

export type { ConsoleOverview };
