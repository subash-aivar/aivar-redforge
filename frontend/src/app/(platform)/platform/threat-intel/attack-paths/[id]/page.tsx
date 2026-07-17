"use client";

import Link from "next/link";
import { use, useEffect, useRef, useState } from "react";
import {
  getAttackPath,
  containAttackPath,
  archiveAttackPath,
  pathConfidenceColor,
  pathStatusColor,
  stepConfidenceColor,
  KILL_CHAIN_ORDER,
  phaseLabel,
  type AttackPath,
  type AttackStep,
} from "@/lib/attackPathsApi";

const NODE_W = 140;
const NODE_H = 44;
const NODE_GAP_X = 20;
const NODE_GAP_Y = 14;
const LANE_HEADER_H = 28;
const CANVAS_PAD = 24;

interface LayoutNode {
  step: AttackStep;
  x: number;
  y: number;
  laneIndex: number;
  colInLane: number;
}

interface Lane {
  phase: string;
  x: number;
  w: number;
  y: number;
  h: number;
}

function buildLayout(steps: AttackStep[]): { nodes: LayoutNode[]; lanes: Lane[]; svgW: number; svgH: number } {
  // Group steps by kill-chain phase, maintaining sequence order within each group.
  const phaseMap = new Map<string, AttackStep[]>();
  for (const s of [...steps].sort((a, b) => a.sequence - b.sequence)) {
    const ph = s.kill_chain_phase ?? "unknown";
    const arr = phaseMap.get(ph) ?? [];
    arr.push(s);
    phaseMap.set(ph, arr);
  }

  // Sort phases by canonical ATT&CK order.
  const sortedPhases = [...phaseMap.keys()].sort(
    (a, b) => (KILL_CHAIN_ORDER[a] ?? 99) - (KILL_CHAIN_ORDER[b] ?? 99),
  );

  const nodes: LayoutNode[] = [];
  const lanes: Lane[] = [];
  let curX = CANVAS_PAD;

  for (let li = 0; li < sortedPhases.length; li++) {
    const phase = sortedPhases[li];
    const stepsInLane = phaseMap.get(phase)!;
    const laneW = stepsInLane.length * NODE_W + (stepsInLane.length - 1) * NODE_GAP_X + CANVAS_PAD * 2;

    const laneY = CANVAS_PAD;
    const laneH = LANE_HEADER_H + NODE_GAP_Y + NODE_H + CANVAS_PAD;

    for (let ci = 0; ci < stepsInLane.length; ci++) {
      const step = stepsInLane[ci];
      const x = curX + CANVAS_PAD + ci * (NODE_W + NODE_GAP_X);
      const y = laneY + LANE_HEADER_H + NODE_GAP_Y;
      nodes.push({ step, x, y, laneIndex: li, colInLane: ci });
    }

    lanes.push({ phase, x: curX, w: laneW, y: laneY, h: laneH });
    curX += laneW + 4;
  }

  const svgW = curX + CANVAS_PAD;
  const svgH = CANVAS_PAD + Math.max(...lanes.map((l) => l.h), LANE_HEADER_H + NODE_H + CANVAS_PAD * 2);

  return { nodes, lanes, svgW, svgH };
}

function nodeById(nodes: LayoutNode[], seqOrEntityId: number | string): LayoutNode | undefined {
  return nodes.find(
    (n) => n.step.sequence === seqOrEntityId || n.step.entity_id === seqOrEntityId,
  );
}

function AttackPathGraph({
  steps,
  selectedSeq,
  onSelect,
}: {
  steps: AttackStep[];
  selectedSeq: number | null;
  onSelect: (seq: number) => void;
}) {
  const { nodes, lanes, svgW, svgH } = buildLayout(steps);
  const svgRef = useRef<SVGSVGElement>(null);

  const edges: { x1: number; y1: number; x2: number; y2: number }[] = [];
  for (const n of nodes) {
    if (n.step.inferred_from_step !== null) {
      const src = nodeById(nodes, n.step.inferred_from_step);
      if (src) {
        edges.push({
          x1: src.x + NODE_W / 2,
          y1: src.y + NODE_H,
          x2: n.x + NODE_W / 2,
          y2: n.y,
        });
      }
    }
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-950">
      <svg
        ref={svgRef}
        width={svgW}
        height={svgH}
        viewBox={`0 0 ${svgW} ${svgH}`}
        className="block"
        aria-label="Attack path graph"
      >
        {/* Lane backgrounds */}
        {lanes.map((l) => (
          <g key={l.phase}>
            <rect
              x={l.x + 2}
              y={l.y}
              width={l.w - 4}
              height={l.h}
              rx={8}
              fill="none"
              stroke="#374151"
              strokeWidth={1}
            />
            <rect
              x={l.x + 2}
              y={l.y}
              width={l.w - 4}
              height={LANE_HEADER_H}
              rx={8}
              fill="#111827"
            />
            <text
              x={l.x + l.w / 2}
              y={l.y + LANE_HEADER_H / 2 + 5}
              textAnchor="middle"
              fontSize={10}
              fill="#9ca3af"
              fontFamily="ui-monospace, monospace"
            >
              {phaseLabel(l.phase)}
            </text>
          </g>
        ))}

        {/* Edges */}
        {edges.map((e, i) => {
          const mx = (e.x1 + e.x2) / 2;
          const my = (e.y1 + e.y2) / 2;
          const path = `M ${e.x1} ${e.y1} C ${e.x1} ${my}, ${e.x2} ${my}, ${e.x2} ${e.y2}`;
          return (
            <path key={i} d={path} fill="none" stroke="#4b5563" strokeWidth={1.5} markerEnd="url(#arr)" />
          );
        })}

        {/* Arrow marker */}
        <defs>
          <marker id="arr" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#4b5563" />
          </marker>
        </defs>

        {/* Nodes */}
        {nodes.map(({ step, x, y }) => {
          const selected = selectedSeq === step.sequence;
          const fill = selected ? "#3b0764" : "#1f2937";
          const stroke = selected ? "#a855f7" : "#374151";
          const textColor = selected ? "#e9d5ff" : "#d1d5db";
          const subColor = selected ? "#c084fc" : "#6b7280";
          const conf = stepConfidenceColor(step.confidence);
          return (
            <g
              key={step.sequence}
              onClick={() => onSelect(step.sequence)}
              style={{ cursor: "pointer" }}
              role="button"
              aria-label={`Step ${step.sequence}: ${step.step_type}`}
            >
              <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={6} fill={fill} stroke={stroke} strokeWidth={1.5} />
              {/* Confidence bar */}
              <rect x={x} y={y + NODE_H - 4} width={NODE_W} height={4} rx={3} fill={conf} opacity={0.6} />
              <text x={x + 8} y={y + 16} fontSize={10} fill={textColor} fontWeight="600" fontFamily="ui-sans-serif, sans-serif">
                {step.step_type.length > 16 ? step.step_type.slice(0, 15) + "…" : step.step_type}
              </text>
              <text x={x + 8} y={y + 30} fontSize={9} fill={subColor} fontFamily="ui-monospace, monospace">
                {step.technique_id ?? `seq:${step.sequence}`}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function AttackPathDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ org?: string }>;
}) {
  const { id } = use(params);
  const { org: orgId = "" } = use(searchParams);

  const [path, setPath] = useState<AttackPath | null>(null);
  const [error, setError] = useState("");
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [actionError, setActionError] = useState("");
  const [actionPending, setActionPending] = useState(false);

  function loadPath() {
    if (!orgId) {
      setError("Organization ID is required. Return to the Attack Paths list and select an organization.");
      return;
    }
    getAttackPath(id, orgId)
      .then((p) => {
        setPath(p);
        if (p.steps && p.steps.length > 0) setSelectedSeq(p.steps[0].sequence);
      })
      .catch(() => setError("Attack path not found or access denied."));
  }

  useEffect(() => { loadPath(); }, [id, orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function doContain() {
    if (!orgId) return;
    setActionPending(true);
    setActionError("");
    try {
      const updated = await containAttackPath(id, orgId);
      setPath(updated);
    } catch {
      setActionError("Contain action failed.");
    } finally {
      setActionPending(false);
    }
  }

  async function doArchive() {
    if (!orgId) return;
    setActionPending(true);
    setActionError("");
    try {
      const updated = await archiveAttackPath(id, orgId);
      setPath(updated);
    } catch {
      setActionError("Archive action failed.");
    } finally {
      setActionPending(false);
    }
  }

  if (error) {
    return (
      <div>
        <Link href="/platform/threat-intel/attack-paths" className="text-xs text-gray-600 hover:text-gray-400">
          ← Attack Paths
        </Link>
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      </div>
    );
  }

  if (!path) return <div className="text-sm text-gray-500">Loading…</div>;

  const selectedStep = path.steps?.find((s) => s.sequence === selectedSeq) ?? null;

  return (
    <div>
      <div className="flex items-center gap-2 text-xs text-gray-600">
        <Link
          href={`/platform/threat-intel/attack-paths${orgId ? `?org=${orgId}` : ""}`}
          className="hover:text-gray-400"
        >
          ← Attack Paths
        </Link>
      </div>

      <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">
            Path <span className="font-mono text-sm text-gray-400">{path.id.slice(0, 12)}…</span>
          </h1>
          <div className="mt-1 text-xs text-gray-500">
            Root: <span className="font-mono text-gray-400">{path.root_canonical_key}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${pathStatusColor(path.status)}`}>
            {path.status}
          </span>
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${pathConfidenceColor(path.path_confidence)}`}>
            confidence: {path.path_confidence}
          </span>
        </div>
      </div>

      {actionError && (
        <div className="mt-2 text-xs text-red-400">{actionError}</div>
      )}

      <div className="mt-3 flex gap-2">
        {path.status === "active" && (
          <button
            onClick={doContain}
            disabled={actionPending}
            className="rounded-lg border border-yellow-800 px-3 py-1.5 text-xs text-yellow-400 hover:bg-yellow-950/50 disabled:opacity-50"
          >
            Contain
          </button>
        )}
        {path.status !== "historical" && (
          <button
            onClick={doArchive}
            disabled={actionPending}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-xs text-gray-400 hover:border-gray-600 hover:text-gray-200 disabled:opacity-50"
          >
            Archive
          </button>
        )}
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Steps" value={String(path.step_count)} />
        <Stat label="Evidence" value={String(path.evidence_count)} />
        <Stat label="Max Exposure" value={path.max_exposure_score.toFixed(2)} />
        <Stat label="Techniques" value={String(path.technique_coverage.length)} />
      </div>

      {path.attributed_actors.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {path.attributed_actors.map((a) => (
            <span
              key={a}
              className="rounded border border-orange-800 bg-orange-950/40 px-2 py-0.5 text-xs text-orange-300"
            >
              {a}
            </span>
          ))}
        </div>
      )}

      {/* Graph */}
      {path.steps && path.steps.length > 0 ? (
        <div className="mt-6">
          <h2 className="mb-2 text-sm font-medium text-gray-300">Kill-Chain Graph</h2>
          <AttackPathGraph
            steps={path.steps}
            selectedSeq={selectedSeq}
            onSelect={setSelectedSeq}
          />
          <p className="mt-1 text-xs text-gray-600">Click a node to inspect it below.</p>
        </div>
      ) : (
        <div className="mt-6 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
          Step detail not loaded — re-fetch the path to include steps.
        </div>
      )}

      {/* Step Detail Panel */}
      {selectedStep && (
        <div className="mt-6 rounded-xl border border-purple-900 bg-gray-900 p-4">
          <h2 className="text-sm font-medium text-purple-300">
            Step {selectedStep.sequence} — {selectedStep.step_type}
          </h2>
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
            <StepField label="Entity ID" value={selectedStep.entity_id.slice(0, 16) + "…"} mono />
            <StepField label="Canonical Key" value={selectedStep.canonical_key} mono />
            <StepField label="Confidence" value={selectedStep.confidence} />
            <StepField label="Technique" value={selectedStep.technique_id ?? "—"} mono />
            <StepField label="Kill-Chain Phase" value={phaseLabel(selectedStep.kill_chain_phase)} />
            <StepField label="Exposure Score" value={selectedStep.exposure_score.toFixed(2)} />
            {selectedStep.relationship_type && (
              <StepField label="Relationship" value={selectedStep.relationship_type} />
            )}
            {selectedStep.inferred_from_step !== null && (
              <StepField label="Inferred From Step" value={String(selectedStep.inferred_from_step)} />
            )}
          </div>
          {selectedStep.evidence_refs.length > 0 && (
            <div className="mt-3">
              <div className="mb-1 text-xs text-gray-600">Evidence refs</div>
              <div className="flex flex-wrap gap-1.5">
                {selectedStep.evidence_refs.map((ref) => (
                  <span
                    key={ref}
                    className="rounded border border-gray-700 bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-400"
                  >
                    {ref}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-3">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="mt-0.5 text-lg font-bold text-white">{value}</div>
    </div>
  );
}

function StepField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-gray-600">{label}</div>
      <div className={`mt-0.5 text-xs ${mono ? "font-mono text-gray-400" : "text-gray-200"}`}>{value}</div>
    </div>
  );
}
