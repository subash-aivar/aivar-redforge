"use client";

/**
 * Enterprise auth-screen visual panel — animated network/telemetry
 * backdrop for the login page's brand side. Pure inline SVG/CSS
 * (matches components/cc.tsx's no-external-library convention; the
 * app's CSP has no allowance for external images or canvases). Purely
 * decorative — aria-hidden, respects prefers-reduced-motion via the
 * .animate-* utilities defined in globals.css.
 */

const NODES = [
  { x: 60, y: 80, r: 3 },
  { x: 180, y: 40, r: 2 },
  { x: 260, y: 120, r: 4 },
  { x: 340, y: 60, r: 2 },
  { x: 120, y: 200, r: 3 },
  { x: 300, y: 220, r: 2 },
  { x: 220, y: 280, r: 3 },
  { x: 380, y: 180, r: 2 },
  { x: 40, y: 300, r: 2 },
  { x: 400, y: 320, r: 3 },
];

const EDGES: [number, number][] = [
  [0, 1], [1, 2], [2, 3], [1, 4], [4, 5], [5, 6], [3, 7], [4, 8], [6, 9], [7, 9],
];

const TELEMETRY_LINES = [
  "AUTH · principal verification pending",
  "RBAC · effective-permission resolution",
  "TENANT · isolation boundary enforced",
  "MFA · privileged-assurance check",
  "AUDIT · session event recorded",
];

export function AuthVisual() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 overflow-hidden bg-gray-950"
    >
      {/* Base grid */}
      <div
        className="absolute inset-0 animate-grid-drift opacity-[0.07]"
        style={{
          backgroundImage:
            "linear-gradient(to right, #ef4444 1px, transparent 1px), linear-gradient(to bottom, #ef4444 1px, transparent 1px)",
          backgroundSize: "64px 64px",
        }}
      />

      {/* Radial glow */}
      <div className="absolute left-1/2 top-1/3 h-[600px] w-[600px] -translate-x-1/2 -translate-y-1/2 animate-pulse-glow rounded-full bg-red-600/10 blur-3xl" />
      <div className="absolute bottom-0 right-0 h-[400px] w-[400px] animate-pulse-glow rounded-full bg-red-500/5 blur-3xl [animation-delay:2s]" />

      {/* Network graph */}
      <svg
        viewBox="0 0 440 360"
        className="absolute left-1/2 top-1/2 h-auto w-[85%] max-w-lg -translate-x-1/2 -translate-y-1/2 opacity-40"
      >
        {EDGES.map(([a, b], i) => (
          <line
            key={i}
            x1={NODES[a].x}
            y1={NODES[a].y}
            x2={NODES[b].x}
            y2={NODES[b].y}
            stroke="#ef4444"
            strokeWidth="0.75"
            strokeOpacity="0.4"
          />
        ))}
        {NODES.map((n, i) => (
          <circle
            key={i}
            cx={n.x}
            cy={n.y}
            r={n.r}
            fill="#f87171"
            className="animate-pulse-glow"
            style={{ animationDelay: `${(i % 5) * 0.6}s` }}
          />
        ))}
      </svg>

      {/* Scan line */}
      <div className="absolute inset-x-0 top-0 h-32 animate-scan-line bg-gradient-to-b from-red-500/10 via-transparent to-transparent" />

      {/* Telemetry ticker */}
      <div className="absolute bottom-32 left-10 right-10 space-y-1.5 font-mono text-[10px] uppercase tracking-widest text-red-400/50">
        {TELEMETRY_LINES.map((line, i) => (
          <div
            key={line}
            className="animate-fade-in-up"
            style={{ animationDelay: `${i * 0.15 + 0.3}s` }}
          >
            <span className="text-red-500/70">›</span> {line}
          </div>
        ))}
      </div>
    </div>
  );
}
