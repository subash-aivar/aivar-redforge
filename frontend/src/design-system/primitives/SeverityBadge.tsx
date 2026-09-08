import { SEVERITY_BADGE_CLASSES, type Severity } from "@/design-system/tokens";

/** Canonical severity badge. Markup is byte-identical to `cc.tsx`'s
 * `SeverityBadge` (border + uppercase + tracking-wider pill) — the
 * platform consistency audit found this primitive had drifted from
 * the dominant standard (no border, sentence-case, larger padding);
 * normalized to match rather than leaving two different badge shapes
 * on screen simultaneously. */
export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase() as Severity;
  const classes = SEVERITY_BADGE_CLASSES[normalized] ?? "border-gray-700 bg-gray-800/60 text-gray-300";
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${classes}`}
    >
      {severity}
    </span>
  );
}
