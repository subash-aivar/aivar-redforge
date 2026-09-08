"use client";

export type TimeRangeValue = "1h" | "24h" | "7d" | "30d" | "90d";

export const TIME_RANGE_OPTIONS: { value: TimeRangeValue; label: string }[] = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

/** Converts a `TimeRangeValue` into an ISO `since` timestamp — the one
 * canonical place this conversion happens, so every dashboard's
 * aggregation call agrees on what "Last 24h" means. */
export function timeRangeToSince(value: TimeRangeValue, now: Date = new Date()): string {
  const hours: Record<TimeRangeValue, number> = { "1h": 1, "24h": 24, "7d": 168, "30d": 720, "90d": 2160 };
  return new Date(now.getTime() - hours[value] * 60 * 60 * 1000).toISOString();
}

interface TimeRangeSelectorProps {
  value: TimeRangeValue;
  onChange: (value: TimeRangeValue) => void;
}

/** Shared time-range control every dashboard/page can compose into its
 * header — replaces one-off range pickers per page. */
export function TimeRangeSelector({ value, onChange }: TimeRangeSelectorProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as TimeRangeValue)}
      className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-gray-300 focus:border-gray-600 focus:outline-none"
      aria-label="Time range"
    >
      {TIME_RANGE_OPTIONS.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}
