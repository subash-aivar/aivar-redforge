"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  DataConsole,
  EmptyRow,
  ErrorRow,
  FilterChip,
  ForbiddenRow,
  LoadingRow,
  PageHeader,
  Panel,
  SearchInput,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  getConsoleOverview,
  listConsoleAssessments,
  type ControlAssessment,
} from "@/lib/compliance";
import {
  controlStatusPillClass,
  statusLabel,
} from "@/lib/compliance-helpers";

const PAGE_SIZE = 50;

export default function AssessmentWorkspaceInner() {
  const searchParams = useSearchParams();
  const periodParam = searchParams.get("period");
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [periodId, setPeriodId] = useState<string | null>(periodParam);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    setPage(0);
  }, [statusFilter, debouncedQuery, periodId, periodParam]);

  const overview = useAsync(() => getConsoleOverview(), []);
  const effectivePeriod = periodId ?? periodParam;

  const list = useAsync(
    () =>
      listConsoleAssessments({
        period_id: effectivePeriod ?? undefined,
        status: statusFilter ?? undefined,
        search: debouncedQuery || undefined,
        sort: "updated_at",
        sort_dir: "desc",
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    [effectivePeriod, statusFilter, debouncedQuery, page]
  );

  const columns: ConsoleColumn<ControlAssessment>[] = useMemo(
    () => [
      {
        key: "id",
        header: "Assessment",
        width: "18%",
        render: (r) => (
          <Link
            href={`/compliance/assessments/${r.id}`}
            className="font-mono text-[11px] text-red-300 hover:text-red-200"
            onClick={(e) => e.stopPropagation()}
          >
            {r.id.slice(0, 14)}…
          </Link>
        ),
      },
      {
        key: "framework",
        header: "Framework",
        width: "12%",
        render: (r) => r.framework_key,
      },
      {
        key: "requirement",
        header: "Requirement",
        width: "18%",
        render: (r) => (
          <span className="font-mono text-[11px]">
            {r.requirement_id.slice(0, 12)}…
          </span>
        ),
      },
      {
        key: "status",
        header: "Status",
        width: "16%",
        render: (r) => (
          <span
            className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${controlStatusPillClass(r.status)}`}
          >
            {statusLabel(r.status)}
          </span>
        ),
      },
      {
        key: "evidence",
        header: "Evidence",
        width: "10%",
        render: (r) => (
          <span className="tabular-nums">{r.evidence_links.length}</span>
        ),
      },
      {
        key: "updated",
        header: "Updated",
        width: "16%",
        render: (r) => fmtTime(r.updated_at),
      },
    ],
    []
  );

  if (overview.loading && list.loading) {
    return (
      <>
        <PageHeader title="Assessment Workspace" />
        <LoadingRow />
      </>
    );
  }
  if (overview.forbidden || list.forbidden) {
    return (
      <>
        <PageHeader title="Assessment Workspace" />
        <ForbiddenRow />
      </>
    );
  }
  if ((overview.error && !overview.data) || (list.error && !list.data)) {
    return (
      <>
        <PageHeader title="Assessment Workspace" />
        <ErrorRow message={overview.error ?? list.error ?? "No data"} />
      </>
    );
  }

  const openPeriods = overview.data?.open_period_summaries ?? [];
  const total = list.data?.total ?? 0;
  const rows = list.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Assessment Workspace"
        subtitle="Control status, evidence, and lifecycle actions"
        actions={
          <button
            type="button"
            onClick={() => {
              overview.reload();
              list.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
          >
            Refresh
          </button>
        }
      />

      <Panel title="Filters" className="mb-4">
        <div className="mb-3 flex flex-wrap gap-2">
          <FilterChip
            label="All periods"
            active={!effectivePeriod}
            onClick={() => setPeriodId(null)}
          />
          {openPeriods.map((p) => (
            <FilterChip
              key={p.id}
              label={p.name}
              active={effectivePeriod === p.id}
              onClick={() => setPeriodId(p.id)}
              tone={p.status === "open" ? "warning" : "neutral"}
            />
          ))}
        </div>
        <div className="mb-3 flex flex-wrap gap-2">
          <FilterChip
            label="All statuses"
            active={!statusFilter}
            onClick={() => setStatusFilter(null)}
          />
          {[
            "not_assessed",
            "collecting_evidence",
            "pending_confirmation",
            "technically_validated",
          ].map((s) => (
            <FilterChip
              key={s}
              label={statusLabel(s)}
              active={statusFilter === s}
              onClick={() => setStatusFilter(s)}
            />
          ))}
        </div>
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search assessment / requirement / framework…"
        />
      </Panel>

      <Panel title={`Assessments (${total})`}>
        {list.loading && <LoadingRow />}
        {!list.loading && rows.length === 0 ? (
          <EmptyRow label="No assessments match the current filters." />
        ) : (
          !list.loading && (
            <>
              <DataConsole columns={columns} rows={rows} rowKey={(r) => r.id} />
              <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
                <span>
                  Page {page + 1} · {PAGE_SIZE} per page
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={page === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    className="rounded border border-gray-800 px-2 py-1 disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <button
                    type="button"
                    disabled={(page + 1) * PAGE_SIZE >= total}
                    onClick={() => setPage((p) => p + 1)}
                    className="rounded border border-gray-800 px-2 py-1 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )
        )}
      </Panel>
    </>
  );
}
