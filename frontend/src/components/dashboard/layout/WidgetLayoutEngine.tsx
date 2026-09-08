import type { ReactNode } from "react";

export type WidgetSpan = 1 | 2 | 3 | 4;

const SPAN_CLASSES: Record<WidgetSpan, string> = {
  1: "lg:col-span-1",
  2: "lg:col-span-2",
  3: "lg:col-span-3",
  4: "lg:col-span-4",
};

export interface LayoutSlot {
  key: string;
  span: WidgetSpan;
  node: ReactNode;
}

interface WidgetLayoutEngineProps {
  slots: LayoutSlot[];
  /** Total columns of the grid at the `lg` breakpoint. Every widget's
   * `span` is relative to this. Defaults to 4, matching the existing
   * `lg:grid-cols-4` KPI row already used in `dashboard/page.tsx`. */
  columns?: WidgetSpan;
}

/**
 * The single responsive grid every dashboard lays widgets into.
 *
 * Mobile: always 1 column. Small: 2 columns. Large: `columns`
 * columns, with each slot spanning `slot.span` of them — mirrors the
 * `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` pattern already used for
 * the KPI row in `dashboard/page.tsx`, generalized so every widget
 * (not just KPI cards) can opt into it.
 */
// Tailwind's content scanner requires complete, literal class names —
// a template-string like `lg:grid-cols-${columns}` would never be
// picked up at build time, so the column-count classes are a static
// lookup instead.
const COLUMN_CLASSES: Record<WidgetSpan, string> = {
  1: "lg:grid-cols-1",
  2: "lg:grid-cols-2",
  3: "lg:grid-cols-3",
  4: "lg:grid-cols-4",
};

export function WidgetLayoutEngine({ slots, columns = 4 }: WidgetLayoutEngineProps) {
  return (
    <div className={`grid grid-cols-1 gap-4 sm:grid-cols-2 ${COLUMN_CLASSES[columns]}`}>
      {slots.map((slot) => (
        <div key={slot.key} className={SPAN_CLASSES[slot.span]}>
          {slot.node}
        </div>
      ))}
    </div>
  );
}
