import dynamic from "next/dynamic";
import type { ColumnDef } from "@tanstack/react-table";
import { KpiCard, type KpiViewModel } from "@/components/dashboard/widgets/KpiCard";
import type { ChartViewModel } from "@/components/dashboard/widgets/ChartWidget";
import { TableWidget, type TableViewModel } from "@/components/dashboard/widgets/TableWidget";
import type { MapViewModel } from "@/components/dashboard/widgets/MapWidget";
import type { GraphViewModel } from "@/components/dashboard/widgets/GraphWidget";
import { TimelineWidget, type TimelineViewModel } from "@/components/dashboard/widgets/TimelineWidget";
import { AlertWidget, type AlertViewModel } from "@/components/dashboard/widgets/AlertWidget";
import { LiveFeedWidget, type LiveFeedWidgetProps } from "@/components/dashboard/widgets/LiveFeedWidget";
import { AwaitingIntegrationWidget } from "@/components/dashboard/widgets/AwaitingIntegrationWidget";
import { WidgetLayoutEngine, type WidgetSpan } from "@/components/dashboard/layout/WidgetLayoutEngine";
import { LoadingState } from "@/design-system/primitives/States";

/**
 * Dashboard Composition Engine.
 *
 * A persona dashboard is declared as a `DashboardSpec` — a flat list
 * of `WidgetSpec` entries, each a discriminated union tagged by
 * `type`. This engine is the ONLY place that switches on `type` and
 * instantiates the concrete widget component; a persona dashboard
 * page itself never imports `KpiCard`/`ChartWidget`/etc. directly, it
 * only builds specs from Dashboard ViewModels (see
 * `dashboard/aggregation/types.ts`) and hands them to
 * `<DashboardCompositionEngine spec={...} />`.
 *
 * Performance: `ChartWidget` (Apache ECharts), `MapWidget` (MapLibre
 * GL), and `GraphWidget` (`@xyflow/react`) are the three heaviest
 * dependencies in the widget framework and are code-split via
 * `next/dynamic` — a dashboard with no chart/map/graph widgets on it
 * never downloads any of that JavaScript. This is why this file
 * imports their *types* only from the static imports above and their
 * *components* only through the lazy factories below.
 */
const ChartWidget = dynamic<ChartViewModel>(
  () => import("@/components/dashboard/widgets/ChartWidget").then((m) => m.ChartWidget),
  { ssr: false, loading: () => <LoadingState label="Loading chart…" /> }
);
const MapWidget = dynamic<MapViewModel>(
  () => import("@/components/dashboard/widgets/MapWidget").then((m) => m.MapWidget),
  { ssr: false, loading: () => <LoadingState label="Loading map…" /> }
);
const GraphWidget = dynamic<GraphViewModel>(
  () => import("@/components/dashboard/widgets/GraphWidget").then((m) => m.GraphWidget),
  { ssr: false, loading: () => <LoadingState label="Loading graph…" /> }
);

export type WidgetSpec =
  | { type: "kpi"; span: WidgetSpan; viewModel: KpiViewModel }
  | { type: "chart"; span: WidgetSpan; viewModel: ChartViewModel }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  | { type: "table"; span: WidgetSpan; viewModel: TableViewModel<any> }
  | { type: "map"; span: WidgetSpan; viewModel: MapViewModel }
  | { type: "graph"; span: WidgetSpan; viewModel: GraphViewModel }
  | { type: "timeline"; span: WidgetSpan; viewModel: TimelineViewModel }
  | { type: "alerts"; span: WidgetSpan; viewModel: AlertViewModel }
  | { type: "live-feed"; span: WidgetSpan; viewModel: LiveFeedWidgetProps & { id: string } }
  | { type: "awaiting-integration"; span: WidgetSpan; viewModel: { id: string; title: string; reason: string } };

export interface DashboardSpec {
  id: string;
  widgets: WidgetSpec[];
  columns?: WidgetSpan;
}

function renderWidget(spec: WidgetSpec) {
  switch (spec.type) {
    case "kpi":
      return <KpiCard {...spec.viewModel} />;
    case "chart":
      return <ChartWidget {...spec.viewModel} />;
    case "table":
      return <TableWidget {...spec.viewModel} columns={spec.viewModel.columns as ColumnDef<unknown, unknown>[]} />;
    case "map":
      return <MapWidget {...spec.viewModel} />;
    case "graph":
      return <GraphWidget {...spec.viewModel} />;
    case "timeline":
      return <TimelineWidget {...spec.viewModel} />;
    case "alerts":
      return <AlertWidget {...spec.viewModel} />;
    case "live-feed":
      return <LiveFeedWidget {...spec.viewModel} />;
    case "awaiting-integration":
      return <AwaitingIntegrationWidget {...spec.viewModel} />;
  }
}

export function DashboardCompositionEngine({ id, widgets, columns }: DashboardSpec) {
  return (
    <WidgetLayoutEngine
      columns={columns}
      slots={widgets.map((spec, index) => ({
        key: `${id}-${spec.type}-${index}`,
        span: spec.span,
        node: renderWidget(spec),
      }))}
    />
  );
}
