/**
 * Canonical attack-graph state mapping and detail rendering — extracted from
 * page.tsx so it can be unit tested (Next.js App Router restricts page.tsx
 * to a fixed set of reserved exports).
 */

export interface CampaignSummary {
  campaign_id: string;
  organization_id: string;
  target_id: string;
  state: string;
  goal_achieved: boolean;
  objective_name: string;
  total_nodes: number;
  nodes_executed: number;
  completed_nodes: number;
  failed_nodes: number;
  blocked_nodes: number;
  intelligence_confidence: number;
  duration_ms: number;
  failure_reason: string | null;
  created_at: string;
}

export interface CampaignDetail extends CampaignSummary {
  graph_nodes: Array<{
    id: string;
    state: string;
    attack_category?: string;
    findings_count?: number;
    evidence_count?: number;
    duration_ms?: number;
    failure_reason?: string | null;
  }>;
  graph_edges: Array<{ source: string; target: string }>;
}

const NODE_STATE_COLORS: Record<string, string> = {
  COMPLETED: "bg-green-950 text-green-400 border-green-800",
  FAILED: "bg-red-950 text-red-400 border-red-800",
  RUNNING: "bg-blue-950 text-blue-400 border-blue-800",
  PENDING: "bg-gray-800 text-gray-400 border-gray-700",
  READY: "bg-yellow-950 text-yellow-400 border-yellow-800",
  BLOCKED: "bg-orange-950 text-orange-400 border-orange-800",
  SKIPPED: "bg-gray-800 text-gray-500 border-gray-700",
  UNKNOWN: "bg-gray-800 text-gray-500 border-gray-700",
};

const CANONICAL_NODE_STATES = [
  "PENDING", "READY", "RUNNING", "COMPLETED",
  "FAILED", "BLOCKED", "SKIPPED",
] as const;

/** Maps a raw API node state to a canonical display state. Unknown/missing values always render UNKNOWN — never silently mapped to a known state. */
export function toCanonicalNodeState(rawState: string | null | undefined): string {
  const upper = (rawState ?? "UNKNOWN").toUpperCase();
  return (CANONICAL_NODE_STATES as readonly string[]).includes(upper) ? upper : "UNKNOWN";
}

export function CampaignDetailView({
  detail,
  onClose,
}: {
  detail: CampaignDetail;
  onClose: () => void;
}) {
  return (
    <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">
          Campaign: {detail.objective_name}
        </h2>
        <button
          onClick={onClose}
          className="text-xs text-gray-500 hover:text-gray-300"
        >
          Close
        </button>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Total Nodes" value={detail.total_nodes} />
        <Stat label="Executed" value={detail.nodes_executed} />
        <Stat label="Completed" value={detail.completed_nodes} />
        <Stat label="Failed" value={detail.failed_nodes} />
      </div>

      {detail.failure_reason && (
        <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
          {detail.failure_reason}
        </div>
      )}

      {detail.graph_nodes.length === 0 ? (
        <div className="mt-4 text-sm text-gray-500">No attack nodes recorded.</div>
      ) : (
        <div className="mt-4">
          <div className="mb-2 text-sm font-medium text-gray-400">Attack Nodes</div>
          <div className="space-y-2">
            {detail.graph_nodes.map((node) => {
              const displayState = toCanonicalNodeState(node.state);
              const colorCls =
                NODE_STATE_COLORS[displayState] ??
                "bg-gray-800 text-gray-400 border-gray-700";
              return (
                <div
                  key={node.id}
                  className={`flex items-center justify-between rounded-lg border px-3 py-2 ${colorCls}`}
                >
                  <div>
                    <div className="text-sm font-medium font-mono">{node.id}</div>
                    {node.attack_category && (
                      <div className="text-xs opacity-70">{node.attack_category}</div>
                    )}
                    {node.failure_reason && (
                      <div className="text-xs text-red-400 mt-0.5">{node.failure_reason}</div>
                    )}
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-mono">{displayState}</div>
                    {node.findings_count !== undefined && node.findings_count > 0 && (
                      <div className="text-xs opacity-60">{node.findings_count} findings</div>
                    )}
                    {node.duration_ms !== undefined && node.duration_ms > 0 && (
                      <div className="text-xs opacity-50">{node.duration_ms}ms</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="mt-4 text-xs text-gray-600">
        Campaign ID: {detail.campaign_id} · {new Date(detail.created_at).toLocaleString()}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="text-xl font-bold text-white">{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}
