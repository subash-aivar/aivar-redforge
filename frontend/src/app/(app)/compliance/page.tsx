"use client";

import Link from "next/link";
import {
  EmptyRow,
  ErrorRow,
  ForbiddenRow,
  GlobalSecurityStrip,
  KpiTile,
  LoadingRow,
  MiniBars,
  PageHeader,
  Panel,
  PostureGauge,
  fmtTime,
  useAsync,
} from "@/components/cc";
import {
  getConsoleOverview,
  listConsoleTimeline,
} from "@/lib/compliance";
import {
  statusLabel,
  controlStatusPillClass,
  barColorForStatus,
} from "@/lib/compliance-helpers";

export default function ComplianceOverviewPage() {
  const overview = useAsync(() => getConsoleOverview(), []);
  const timeline = useAsync(
    () => listConsoleTimeline({ limit: 12, offset: 0 }),
    []
  );

  if (overview.loading) {
    return (
      <>
        <PageHeader
          title="Compliance Operations"
          subtitle="Enterprise compliance posture console"
        />
        <LoadingRow label="Loading compliance posture…" />
      </>
    );
  }
  if (overview.forbidden) {
    return (
      <>
        <PageHeader title="Compliance Operations" />
        <ForbiddenRow />
      </>
    );
  }
  if (overview.error || !overview.data) {
    return (
      <>
        <PageHeader title="Compliance Operations" />
        <ErrorRow message={overview.error ?? "No data"} />
      </>
    );
  }

  const data = overview.data;
  const stats = data.recommendation_counts;
  const dist = Object.entries(data.status_counts).map(([label, value]) => ({
    label: statusLabel(label),
    value,
  }));
  const frameworkProgress = data.framework_progress.map((f) => ({
    label: f.framework_key,
    value: f.coverage_pct,
  }));

  return (
    <>
      <PageHeader
        title="Compliance Operations"
        subtitle="Posture, assessments, evidence, and recommendation workflow"
        actions={
          <button
            type="button"
            onClick={() => {
              overview.reload();
              timeline.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
          >
            Refresh
          </button>
        }
      />

      <GlobalSecurityStrip
        metrics={[
          {
            label: "Open Periods",
            value: data.open_periods,
            tone: data.open_periods > 0 ? "warning" : "ok",
            href: "/compliance/assessments",
          },
          {
            label: "Assessments",
            value: data.assessments_total,
            tone: "neutral",
            href: "/compliance/assessments",
          },
          {
            label: "Validated",
            value: data.validated_count,
            tone: "ok",
          },
          {
            label: "Evidence Links",
            value: data.evidence_link_count,
            tone: "neutral",
            href: "/compliance/evidence",
          },
          {
            label: "Rec. Queue",
            value: stats.recommended,
            tone: stats.recommended > 0 ? "high" : "ok",
            href: "/compliance/recommendations",
          },
          {
            label: "Accepted",
            value: stats.accepted,
            tone: "neutral",
          },
          {
            label: "Linked",
            value: stats.linked,
            tone: "ok",
          },
          {
            label: "Rejected",
            value: stats.rejected,
            tone: stats.rejected > 0 ? "warning" : "neutral",
          },
        ]}
      />

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Panel title="Overall Posture" className="lg:col-span-1">
          <div className="flex flex-col items-center">
            <PostureGauge score={data.posture_score} band={data.posture_band} />
            <p className="mt-2 text-center text-xs text-gray-500">
              {data.validated_count}/{data.assessments_total} controls technically
              validated
            </p>
          </div>
        </Panel>
        <Panel title="Control Status Distribution" className="lg:col-span-1">
          {data.assessments_total === 0 ? (
            <EmptyRow label="No control assessments yet." />
          ) : (
            <MiniBars data={dist} colorFor={barColorForStatus} />
          )}
        </Panel>
        <Panel title="Framework Coverage %" className="lg:col-span-1">
          {frameworkProgress.length === 0 ? (
            <EmptyRow label="No published frameworks visible." />
          ) : (
            <MiniBars data={frameworkProgress} colorFor={() => "#34d399"} />
          )}
        </Panel>
      </div>

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile label="Profiles" value={data.profiles} />
        <KpiTile
          label="Evidence Coverage"
          value={`${data.assessments_with_evidence}/${data.assessments_total || 0}`}
          hint="Assessments with ≥1 confirmed link"
          tone={
            data.assessments_with_evidence < data.assessments_total
              ? "warning"
              : "ok"
          }
        />
        <KpiTile
          label="Acceptance Rate"
          value={`${data.acceptance_pct}%`}
          hint="Accepted + linked over decided"
          tone="ok"
        />
        <KpiTile label="Recommendation Total" value={stats.total} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Active Assessment Periods"
          right={
            <Link
              href="/compliance/assessments"
              className="text-[11px] text-red-400 hover:text-red-300"
            >
              Workspace →
            </Link>
          }
        >
          {data.open_period_summaries.length === 0 ? (
            <EmptyRow label="No open assessment periods." />
          ) : (
            <ul className="divide-y divide-gray-800">
              {data.open_period_summaries.map((p) => (
                <li
                  key={p.id}
                  className="flex items-center justify-between gap-3 py-2 text-sm"
                >
                  <div>
                    <div className="font-medium text-gray-200">{p.name}</div>
                    <div className="text-xs text-gray-500">
                      {p.framework_key} · {fmtTime(p.period_start)} →{" "}
                      {fmtTime(p.period_end)}
                    </div>
                  </div>
                  <Link
                    href={`/compliance/assessments?period=${p.id}`}
                    className="text-xs text-red-400 hover:text-red-300"
                  >
                    Open
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Recently Validated Controls">
          {data.recently_validated.length === 0 ? (
            <EmptyRow label="No technically validated controls yet." />
          ) : (
            <ul className="divide-y divide-gray-800">
              {data.recently_validated.map((a) => (
                <li key={a.id} className="flex items-center justify-between py-2 text-sm">
                  <div>
                    <Link
                      href={`/compliance/assessments/${a.id}`}
                      className="font-mono text-xs text-gray-300 hover:text-red-300"
                    >
                      {a.id.slice(0, 12)}…
                    </Link>
                    <div className="text-xs text-gray-500">
                      {a.framework_key} · {a.evidence_count} evidence
                    </div>
                  </div>
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${controlStatusPillClass(a.status)}`}
                  >
                    {statusLabel(a.status)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Recent Activity"
          className="lg:col-span-2"
          right={
            <Link
              href="/compliance/timeline"
              className="text-[11px] text-red-400 hover:text-red-300"
            >
              Full timeline →
            </Link>
          }
        >
          {timeline.loading && <LoadingRow label="Loading activity…" />}
          {!timeline.loading && (timeline.data?.items.length ?? 0) === 0 && (
            <EmptyRow label="No compliance activity yet." />
          )}
          {!timeline.loading && timeline.data && timeline.data.items.length > 0 && (
            <ol className="space-y-2">
              {timeline.data.items.map((ev) => (
                <li
                  key={ev.id}
                  className="flex items-start gap-3 border-l-2 border-gray-800 pl-3 text-sm"
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-gray-200">{ev.title}</div>
                    <div className="truncate text-xs text-gray-500">{ev.detail}</div>
                  </div>
                  <time className="shrink-0 text-[11px] tabular-nums text-gray-600">
                    {fmtTime(ev.at)}
                  </time>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>
    </>
  );
}
