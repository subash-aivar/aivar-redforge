"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  DataConsole,
  EmptyRow,
  ErrorRow,
  FilterChip,
  ForbiddenRow,
  InvestigationDrawer,
  LoadingRow,
  PageHeader,
  Panel,
  SearchInput,
  fmtTime,
  useAsync,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import { ApiError } from "@/lib/api";
import {
  acceptRecommendation,
  generateRecommendations,
  getConsoleOverview,
  linkRecommendation,
  listConsoleRecommendations,
  rejectRecommendation,
  type EvidenceRecommendation,
} from "@/lib/compliance";
import {
  confidencePillClass,
  recommendationStatusPillClass,
  sourceKindLabel,
  statusLabel,
} from "@/lib/compliance-helpers";

const PAGE_SIZE = 50;

export default function RecommendationQueueInner() {
  const searchParams = useSearchParams();
  const focusId = searchParams.get("id");
  const assessmentFilter = searchParams.get("assessment");

  const [statusFilter, setStatusFilter] = useState<string | null>("recommended");
  const [confidenceFilter, setConfidenceFilter] = useState<string | null>(null);
  const [frameworkFilter, setFrameworkFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [selected, setSelected] = useState<EvidenceRecommendation | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [genBusy, setGenBusy] = useState(false);
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState("updated_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    setPage(0);
  }, [
    statusFilter,
    confidenceFilter,
    frameworkFilter,
    assessmentFilter,
    debouncedQuery,
    sort,
    sortDir,
  ]);

  const overview = useAsync(() => getConsoleOverview(), []);
  const openPeriodId = overview.data?.open_period_summaries[0]?.id ?? null;

  const list = useAsync(
    () =>
      listConsoleRecommendations({
        status: statusFilter ?? undefined,
        confidence: confidenceFilter ?? undefined,
        framework_key: frameworkFilter ?? undefined,
        assessment_id: assessmentFilter ?? undefined,
        search: debouncedQuery || undefined,
        sort,
        sort_dir: sortDir,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    [
      statusFilter,
      confidenceFilter,
      frameworkFilter,
      assessmentFilter,
      debouncedQuery,
      sort,
      sortDir,
      page,
    ]
  );

  const rows = list.data?.items ?? [];
  const total = list.data?.total ?? 0;

  const focused =
    selected ?? rows.find((r) => r.id === focusId) ?? null;

  async function mutate(
    id: string,
    fn: () => Promise<EvidenceRecommendation>
  ) {
    setBusyId(id);
    setActionError(null);
    try {
      const updated = await fn();
      setSelected(updated);
      list.reload();
      overview.reload();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : "Action failed");
    } finally {
      setBusyId(null);
    }
  }

  async function onGenerate() {
    if (!openPeriodId) return;
    setGenBusy(true);
    setActionError(null);
    try {
      await generateRecommendations(openPeriodId, {});
      list.reload();
      overview.reload();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : "Generate failed");
    } finally {
      setGenBusy(false);
    }
  }

  const frameworks = useMemo(() => {
    const keys = new Set(
      (overview.data?.framework_progress ?? []).map((f) => f.framework_key)
    );
    return [...keys].sort();
  }, [overview.data]);

  const columns: ConsoleColumn<EvidenceRecommendation>[] = [
    {
      key: "confidence",
      header: "Confidence",
      width: "12%",
      render: (r) => (
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${confidencePillClass(r.confidence)}`}
        >
          {statusLabel(r.confidence)}
        </span>
      ),
    },
    {
      key: "source",
      header: "Source",
      width: "16%",
      render: (r) => sourceKindLabel(r.primary_reference.source_kind),
    },
    {
      key: "entity",
      header: "Evidence Ref",
      width: "18%",
      render: (r) => (
        <span className="font-mono text-[11px]">
          {r.primary_reference.source_entity_id.slice(0, 16)}…
        </span>
      ),
    },
    {
      key: "score",
      header: "Score",
      width: "8%",
      render: (r) => (
        <span className="tabular-nums">{r.score.toFixed(2)}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "12%",
      render: (r) => (
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${recommendationStatusPillClass(r.status)}`}
        >
          {statusLabel(r.status)}
        </span>
      ),
    },
    {
      key: "rationale",
      header: "Rationale",
      render: (r) => (
        <span className="line-clamp-2 text-gray-400">{r.rationale || "—"}</span>
      ),
    },
  ];

  const drawerFields: DrawerField[] = focused
    ? [
        { label: "ID", value: focused.id },
        { label: "Status", value: statusLabel(focused.status) },
        { label: "Confidence", value: statusLabel(focused.confidence) },
        { label: "Score", value: focused.score.toFixed(3) },
        {
          label: "Source",
          value: `${focused.primary_reference.source_kind} / ${focused.primary_reference.source_entity_id}`,
        },
        { label: "Assessment", value: focused.assessment_id },
        {
          label: "Signals",
          value:
            focused.candidates.flatMap((c) => c.signals).join(", ") || "—",
        },
        { label: "Rationale", value: focused.rationale || "—" },
        {
          label: "Candidates",
          value: (
            <ul className="mt-1 space-y-2">
              {focused.candidates.map((c, i) => (
                <li
                  key={`${c.reference.source_entity_id}-${i}`}
                  className="rounded border border-gray-800 bg-gray-950/50 p-2 text-xs"
                >
                  <div>
                    {c.reference.source_kind}:{c.reference.source_entity_id}
                  </div>
                  <div>
                    raw {c.raw_score.toFixed(2)} ·{" "}
                    {c.signals.join(", ") || "no signals"}
                  </div>
                  <div className="text-gray-500">{c.rationale}</div>
                </li>
              ))}
            </ul>
          ),
        },
        ...(focused.decision
          ? [
              {
                label: "Decision",
                value: `${focused.decision.decided_by} · ${fmtTime(focused.decision.decided_at)} · ${focused.decision.rationale || "—"}`,
              } satisfies DrawerField,
            ]
          : []),
        {
          label: "Actions",
          value: (
            <div className="mt-1 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={
                  busyId === focused.id || focused.status !== "recommended"
                }
                onClick={() =>
                  void mutate(focused.id, () => acceptRecommendation(focused.id))
                }
                className="rounded-md border border-sky-800 bg-sky-950/40 px-3 py-1.5 text-xs font-semibold text-sky-300 disabled:opacity-40"
              >
                Accept
              </button>
              <button
                type="button"
                disabled={
                  busyId === focused.id ||
                  (focused.status !== "recommended" &&
                    focused.status !== "accepted")
                }
                onClick={() =>
                  void mutate(focused.id, () => rejectRecommendation(focused.id))
                }
                className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 disabled:opacity-40"
              >
                Reject
              </button>
              <button
                type="button"
                disabled={
                  busyId === focused.id || focused.status !== "accepted"
                }
                onClick={() =>
                  void mutate(focused.id, () => linkRecommendation(focused.id))
                }
                className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 disabled:opacity-40"
              >
                Link
              </button>
            </div>
          ),
        },
        { label: "Updated", value: fmtTime(focused.updated_at) },
      ]
    : [];

  if (list.loading && !list.data && overview.loading) {
    return (
      <>
        <PageHeader title="Recommendation Review Queue" />
        <LoadingRow />
      </>
    );
  }
  if (list.forbidden || overview.forbidden) {
    return (
      <>
        <PageHeader title="Recommendation Review Queue" />
        <ForbiddenRow />
      </>
    );
  }
  if (list.error && !list.data) {
    return (
      <>
        <PageHeader title="Recommendation Review Queue" />
        <ErrorRow message={list.error} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Recommendation Review Queue"
        subtitle="Human review required — never auto-certifies compliance"
        actions={
          <div className="flex gap-2">
            <button
              type="button"
              disabled={!openPeriodId || genBusy}
              onClick={() => void onGenerate()}
              className="rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
            >
              {genBusy ? "Generating…" : "Generate"}
            </button>
            <button
              type="button"
              onClick={() => {
                list.reload();
                overview.reload();
              }}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
            >
              Refresh
            </button>
          </div>
        }
      />

      {actionError && (
        <div className="mb-4">
          <ErrorRow message={actionError} />
        </div>
      )}

      <Panel title="Queue Filters" className="mb-4">
        <div className="mb-3 flex flex-wrap gap-2">
          {["recommended", "accepted", "linked", "rejected"].map((s) => (
            <FilterChip
              key={s}
              label={statusLabel(s)}
              active={statusFilter === s}
              onClick={() => setStatusFilter(s)}
            />
          ))}
          <FilterChip
            label="All statuses"
            active={statusFilter === null}
            onClick={() => setStatusFilter(null)}
          />
        </div>
        <div className="mb-3 flex flex-wrap gap-2">
          {["very_high", "high", "medium", "low", "very_low"].map((c) => (
            <FilterChip
              key={c}
              label={statusLabel(c)}
              active={confidenceFilter === c}
              onClick={() =>
                setConfidenceFilter((cur) => (cur === c ? null : c))
              }
            />
          ))}
        </div>
        {frameworks.length > 0 && (
          <div className="mb-3 flex flex-wrap gap-2">
            <FilterChip
              label="All frameworks"
              active={!frameworkFilter}
              onClick={() => setFrameworkFilter(null)}
            />
            {frameworks.map((fw) => (
              <FilterChip
                key={fw}
                label={fw}
                active={frameworkFilter === fw}
                onClick={() => setFrameworkFilter(fw)}
              />
            ))}
          </div>
        )}
        <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-gray-400">
          <span>Sort:</span>
          {(
            [
              ["updated_at", "Updated"],
              ["score", "Score"],
              ["confidence", "Confidence"],
              ["status", "Status"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                if (sort === key) {
                  setSortDir((d) => (d === "asc" ? "desc" : "asc"));
                } else {
                  setSort(key);
                  setSortDir("desc");
                }
              }}
              className={`rounded border px-2 py-1 ${
                sort === key
                  ? "border-red-800 text-red-300"
                  : "border-gray-800 text-gray-500"
              }`}
            >
              {label}
              {sort === key ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
            </button>
          ))}
        </div>
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search rationale / source / id…"
        />
      </Panel>

      <Panel title={`Recommendations (${total})`}>
        {list.loading && <LoadingRow />}
        {!list.loading && rows.length === 0 ? (
          <EmptyRow label="No recommendations in this view." />
        ) : (
          !list.loading && (
            <>
              <DataConsole
                columns={columns}
                rows={rows}
                rowKey={(r) => r.id}
                selectedKey={focused?.id}
                onRowClick={(r) => setSelected(r)}
              />
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

      <InvestigationDrawer
        open={focused != null}
        onClose={() => setSelected(null)}
        title="Evidence Recommendation"
        subtitle={focused ? statusLabel(focused.status) : undefined}
        fields={drawerFields}
        links={
          focused
            ? [
                {
                  label: "Open assessment",
                  href: `/compliance/assessments/${focused.assessment_id}`,
                },
              ]
            : undefined
        }
      />
    </>
  );
}
