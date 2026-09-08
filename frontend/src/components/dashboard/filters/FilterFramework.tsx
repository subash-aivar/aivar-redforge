"use client";

import { Filter, X } from "lucide-react";

export type FilterValue = string | null;

export interface FilterOption {
  value: string;
  label: string;
}

export interface FilterDef {
  id: string;
  label: string;
  options: FilterOption[];
}

export type FilterState = Record<string, FilterValue>;

interface FilterFrameworkProps {
  filters: FilterDef[];
  state: FilterState;
  onChange: (id: string, value: FilterValue) => void;
  onClear?: () => void;
}

/**
 * Generic, closed-vocabulary filter bar.
 *
 * Every dashboard/page declares its own `FilterDef[]` (e.g. severity,
 * source domain, status) built from the enums its own bounded-context
 * API already returns — this component only renders whatever it's
 * given, never invents filter options.
 */
export function FilterFramework({ filters, state, onChange, onClear }: FilterFrameworkProps) {
  const activeCount = Object.values(state).filter((v) => v !== null && v !== "").length;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Filter className="h-4 w-4 text-gray-600" aria-hidden="true" />
      {filters.map((filter) => (
        <select
          key={filter.id}
          value={state[filter.id] ?? ""}
          onChange={(e) => onChange(filter.id, e.target.value || null)}
          className="rounded-lg border border-gray-800 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-300 focus:border-gray-600 focus:outline-none"
        >
          <option value="">{filter.label}: All</option>
          {filter.options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {filter.label}: {opt.label}
            </option>
          ))}
        </select>
      ))}
      {activeCount > 0 && onClear && (
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300"
        >
          <X className="h-3 w-3" aria-hidden="true" />
          Clear ({activeCount})
        </button>
      )}
    </div>
  );
}
