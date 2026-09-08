"use client";

import ReactECharts from "echarts-for-react";
import type { EChartsOption } from "echarts";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState, LoadingState } from "@/design-system/primitives/States";
import { ECHARTS_DARK_THEME } from "@/design-system/tokens";

export interface ChartViewModel {
  id: string;
  title: string;
  /** A fully-formed ECharts option built by the aggregation layer.
   * The widget never invents series/axes — it only merges the shared
   * dark theme in and renders. */
  option: EChartsOption;
  height?: number;
  isLoading?: boolean;
  isEmpty?: boolean;
  emptyMessage?: string;
}

/** Reusable Apache ECharts widget. The single place ECharts is
 * imported/configured — no page should import `echarts-for-react`
 * directly. */
export function ChartWidget({
  title,
  option,
  height = 280,
  isLoading,
  isEmpty,
  emptyMessage = "No data for the selected range.",
}: ChartViewModel) {
  const mergedOption: EChartsOption = {
    ...ECHARTS_DARK_THEME,
    ...option,
  };

  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {isLoading ? (
          <LoadingState />
        ) : isEmpty ? (
          <EmptyState message={emptyMessage} />
        ) : (
          <ReactECharts
            option={mergedOption}
            style={{ height }}
            opts={{ renderer: "canvas" }}
            notMerge
            lazyUpdate
          />
        )}
      </div>
    </Card>
  );
}
