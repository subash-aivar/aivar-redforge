import { PlugZap } from "lucide-react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";

/**
 * Honest placeholder for a named visualization that has no real
 * backing data source yet — per the platform-realization rule
 * ("if data is unavailable, display an honest 'Awaiting platform
 * integration' state; never fabricate"). Distinct from `EmptyState`
 * (which means "the real endpoint returned zero rows") — this means
 * "the endpoint/aggregate this needs does not exist in the backend
 * yet," and says so explicitly rather than rendering a chart with
 * invented numbers.
 */
export function AwaitingIntegrationWidget({
  title,
  reason,
}: {
  title: string;
  reason: string;
}) {
  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3 flex flex-col items-center justify-center gap-2 py-10 text-center">
        <PlugZap className="h-6 w-6 text-gray-600" aria-hidden="true" />
        <p className="text-sm font-medium text-gray-400">Awaiting platform integration</p>
        <p className="max-w-sm text-xs text-gray-600">{reason}</p>
      </div>
    </Card>
  );
}
