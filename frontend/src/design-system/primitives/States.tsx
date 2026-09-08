import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

/** Canonical loading state for any widget/panel/page body. */
export function LoadingState({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-sm text-gray-500">
      <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

/** Canonical empty state — replaces per-page strings like
 * "No findings yet. Run a red-team campaign to generate security findings."
 * with one consistent shape (icon + message + optional action). */
export function EmptyState({
  message,
  action,
}: {
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <Inbox className="h-6 w-6 text-gray-600" aria-hidden="true" />
      <p className="max-w-sm text-sm text-gray-500">{message}</p>
      {action}
    </div>
  );
}

/** Canonical error state. Surface classes are byte-identical to
 * `cc.tsx`'s `ErrorRow` (`border-red-900/60 bg-red-950/40`) — the
 * consistency audit found this primitive used opaque `bg-red-950` and
 * a brighter `border-red-800`, a visibly different (harsher) red
 * banner than the rest of the platform. */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div className="flex-1">
        <p>{message}</p>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="mt-2 text-xs font-medium text-red-200 underline underline-offset-2 hover:text-white"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
}
