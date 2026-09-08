"use client";

import { useCallback, useEffect, useState } from "react";
import type { DashboardAggregator, DashboardLoadParams } from "@/components/dashboard/aggregation/types";
import type { DashboardSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";

interface UseDashboardAggregationResult {
  spec: DashboardSpec | null;
  isLoading: boolean;
  error: string | null;
  reload: () => void;
}

/** The one hook every persona dashboard page uses to run its
 * `DashboardAggregator`. Owns loading/error state so pages never
 * hand-roll their own `useEffect`+`useState` fetch boilerplate for
 * dashboard data (that boilerplate is exactly what
 * `dashboard/page.tsx` currently repeats and this replaces). */
export function useDashboardAggregation(
  aggregator: DashboardAggregator,
  params: DashboardLoadParams
): UseDashboardAggregationResult {
  const [spec, setSpec] = useState<DashboardSpec | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  const reload = useCallback(() => setReloadToken((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);
    aggregator
      .load(params)
      .then((result) => {
        if (!cancelled) setSpec(result);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          // eslint-disable-next-line no-console
          console.error(`dashboard aggregation "${aggregator.id}" failed:`, e);
          setError("Failed to load dashboard data.");
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aggregator.id, params.timeRange, JSON.stringify(params.filters), reloadToken]);

  return { spec, isLoading, error, reload };
}
