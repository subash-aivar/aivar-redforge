import type { DashboardSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";
import type { TimeRangeValue } from "@/components/dashboard/filters/TimeRangeSelector";
import type { FilterState } from "@/components/dashboard/filters/FilterFramework";

/**
 * Dashboard Aggregation Layer contract.
 *
 *     Bounded Context APIs
 *             |
 *     Dashboard Aggregation Layer   <- this file's `DashboardAggregator`
 *             |
 *     Dashboard DTO/ViewModel       <- `DashboardSpec` (widget-shaped)
 *             |
 *     Reusable Widgets
 *             |
 *     Persona Dashboard
 *
 * A widget NEVER calls `src/lib/*.ts` (the bounded-context API clients)
 * directly. Every persona dashboard page calls exactly one
 * `DashboardAggregator.load()`, which is the only place bounded-context
 * responses are read, merged, and shaped into `DashboardSpec` widget
 * view-models. This is the single dashboard data contract — no widget
 * or page should invent a second one.
 */
export interface DashboardLoadParams {
  timeRange: TimeRangeValue;
  filters: FilterState;
}

export interface DashboardAggregator {
  id: string;
  load: (params: DashboardLoadParams) => Promise<DashboardSpec>;
}
