import { STATUS_TONE_CLASSES, statusToTone } from "@/design-system/tokens";

/** Canonical status indicator — replaces the ad hoc
 * `status === "healthy" ? "text-green-400" : "text-yellow-400"`
 * ternaries repeated per-page with `statusToTone`'s single mapping. */
export function StatusBadge({ status }: { status: string }) {
  const tone = statusToTone(status);
  return <span className={`text-xs font-medium ${STATUS_TONE_CLASSES[tone]}`}>{status}</span>;
}
