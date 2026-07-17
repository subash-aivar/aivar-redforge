"use client";

import {
  EmptyRow,
  ErrorRow,
  ForbiddenRow,
  KpiTile,
  LoadingRow,
  MiniBars,
  PageHeader,
  Panel,
  PostureGauge,
  useAsync,
} from "@/components/cc";
import { getConsoleAnalytics } from "@/lib/compliance";
import { barColorForStatus } from "@/lib/compliance-helpers";

/** Simple sparkline from monthly buckets provided by the analytics API. */
function TrendSparkline({
  points,
  label,
}: {
  points: { label: string; value: number }[];
  label: string;
}) {
  if (points.length === 0) {
    return <EmptyRow label={`No ${label} trend data.`} />;
  }
  const max = Math.max(1, ...points.map((p) => p.value));
  const w = 320;
  const h = 80;
  const step = w / Math.max(1, points.length - 1);
  const coords = points.map((p, i) => {
    const x = i * step;
    const y = h - (p.value / max) * (h - 8) - 4;
    return `${x},${y}`;
  });
  const poly = coords.join(" ");
  return (
    <div>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="w-full"
        role="img"
        aria-label={`${label} trend`}
      >
        <polyline
          fill="none"
          stroke="#ef4444"
          strokeWidth="2"
          points={poly}
        />
        {points.map((p, i) => (
          <circle
            key={p.label}
            cx={i * step}
            cy={h - (p.value / max) * (h - 8) - 4}
            r="2.5"
            fill="#f87171"
          />
        ))}
      </svg>
      <div className="mt-1 flex justify-between text-[10px] text-gray-600">
        <span>{points[0]?.label}</span>
        <span>{points[points.length - 1]?.label}</span>
      </div>
    </div>
  );
}

export default function ComplianceAnalyticsPage() {
  const state = useAsync(() => getConsoleAnalytics(), []);

  if (state.loading) {
    return (
      <>
        <PageHeader title="Compliance Analytics" />
        <LoadingRow />
      </>
    );
  }
  if (state.forbidden) {
    return (
      <>
        <PageHeader title="Compliance Analytics" />
        <ForbiddenRow />
      </>
    );
  }
  if (state.error || !state.data) {
    return (
      <>
        <PageHeader title="Compliance Analytics" />
        <ErrorRow message={state.error ?? "No data"} />
      </>
    );
  }

  const charts = state.data;

  return (
    <>
      <PageHeader
        title="Compliance Analytics"
        subtitle="Coverage, acceptance, evidence growth, and validation velocity from live APIs"
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile
          label="Posture Score"
          value={charts.posture_score}
          hint={charts.posture_band}
          tone="ok"
        />
        <KpiTile
          label="Acceptance Rate"
          value={`${charts.acceptance_pct}%`}
          tone="ok"
        />
        <KpiTile label="Evidence Links" value={charts.evidence_link_count} />
        <KpiTile
          label="Validated Controls"
          value={`${charts.validated_count}/${charts.assessments_total}`}
          tone="ok"
        />
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Panel title="Overall Posture">
          <div className="flex justify-center">
            <PostureGauge
              score={charts.posture_score}
              band={charts.posture_band}
            />
          </div>
        </Panel>
        <Panel title="Control Status Distribution">
          {charts.status_distribution.every((d) => d.value === 0) ? (
            <EmptyRow label="No assessments to chart." />
          ) : (
            <MiniBars
              data={charts.status_distribution}
              colorFor={barColorForStatus}
            />
          )}
        </Panel>
        <Panel title="Framework Coverage %">
          {charts.framework_coverage.length === 0 ? (
            <EmptyRow label="No frameworks." />
          ) : (
            <MiniBars
              data={charts.framework_coverage}
              colorFor={() => "#34d399"}
            />
          )}
        </Panel>
        <Panel title="Recommendation Acceptance Mix">
          <MiniBars
            data={charts.recommendation_acceptance_mix}
            colorFor={(label) =>
              label === "rejected"
                ? "#f87171"
                : label === "linked"
                  ? "#34d399"
                  : label === "accepted"
                    ? "#38bdf8"
                    : "#fbbf24"
            }
          />
        </Panel>
        <Panel title="Evidence Growth (by month)">
          <TrendSparkline
            points={charts.evidence_growth}
            label="evidence growth"
          />
        </Panel>
        <Panel title="Validation Velocity (by month)">
          <TrendSparkline
            points={charts.validation_velocity}
            label="validation velocity"
          />
        </Panel>
        <Panel title="Compliance Trend (% validated)" className="lg:col-span-2">
          <TrendSparkline
            points={charts.compliance_trend}
            label="compliance trend"
          />
        </Panel>
      </div>
    </>
  );
}
