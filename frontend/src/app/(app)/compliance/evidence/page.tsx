"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
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
  listConsoleEvidence,
  type ConsoleEvidenceRow,
} from "@/lib/compliance";
import { sourceKindLabel, statusLabel } from "@/lib/compliance-helpers";

const CATEGORIES: { key: string; label: string }[] = [
  { key: "all", label: "All" },
  { key: "confirmed", label: "Confirmed" },
  { key: "recommended", label: "Recommended" },
  { key: "investigation_evidence", label: "Investigation" },
  { key: "threat_intelligence", label: "Threat Intel" },
  { key: "cloud_scan", label: "Cloud Scan" },
];

const PAGE_SIZE = 50;

export default function EvidenceExplorerPage() {
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [sortKey, setSortKey] = useState("updated_at");
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    setPage(0);
  }, [category, debouncedQuery, sortKey, sortAsc]);

  const list = useAsync(
    () =>
      listConsoleEvidence({
        category: category === "all" ? undefined : category,
        search: debouncedQuery || undefined,
        sort: sortKey,
        sort_dir: sortAsc ? "asc" : "desc",
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    [category, debouncedQuery, sortKey, sortAsc, page]
  );

  const columns: ConsoleColumn<ConsoleEvidenceRow>[] = [
    {
      key: "category",
      header: "Category",
      width: "14%",
      render: (r) => statusLabel(r.category),
    },
    {
      key: "source",
      header: "Source",
      width: "16%",
      render: (r) => sourceKindLabel(r.source_kind),
    },
    {
      key: "entity",
      header: "Entity",
      width: "18%",
      render: (r) => (
        <span className="font-mono text-[11px]">{r.entity_id.slice(0, 18)}…</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "12%",
      render: (r) => statusLabel(r.status),
    },
    {
      key: "confidence",
      header: "Confidence",
      width: "12%",
      render: (r) => (r.confidence ? statusLabel(r.confidence) : "—"),
    },
    {
      key: "updated",
      header: "Updated",
      width: "14%",
      render: (r) => fmtTime(r.updated_at),
    },
    {
      key: "link",
      header: "",
      width: "10%",
      render: (r) =>
        r.assessment_id ? (
          <Link
            href={`/compliance/assessments/${r.assessment_id}`}
            className="text-[11px] text-red-400 hover:text-red-300"
          >
            Assessment
          </Link>
        ) : (
          "—"
        ),
    },
  ];

  if (list.loading && !list.data) {
    return (
      <>
        <PageHeader title="Evidence Explorer" />
        <LoadingRow />
      </>
    );
  }
  if (list.forbidden) {
    return (
      <>
        <PageHeader title="Evidence Explorer" />
        <ForbiddenRow />
      </>
    );
  }
  if (list.error && !list.data) {
    return (
      <>
        <PageHeader title="Evidence Explorer" />
        <ErrorRow message={list.error} />
      </>
    );
  }

  const rows = list.data?.items ?? [];
  const total = list.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Evidence Explorer"
        subtitle="Confirmed, recommended, investigation, TI, and cloud-scan references"
      />

      <Panel title="Filters & Sort" className="mb-4">
        <div className="mb-3 flex flex-wrap gap-2">
          {CATEGORIES.map((c) => (
            <FilterChip
              key={c.key}
              label={c.label}
              active={category === c.key}
              onClick={() => setCategory(c.key)}
            />
          ))}
        </div>
        <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-gray-400">
          <span>Sort:</span>
          {(
            [
              ["updated_at", "Updated"],
              ["entity_id", "Entity"],
              ["source_kind", "Source"],
              ["status", "Status"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                if (sortKey === key) setSortAsc((v) => !v);
                else {
                  setSortKey(key);
                  setSortAsc(false);
                }
              }}
              className={`rounded border px-2 py-1 ${
                sortKey === key
                  ? "border-red-800 text-red-300"
                  : "border-gray-800 text-gray-500"
              }`}
            >
              {label}
              {sortKey === key ? (sortAsc ? " ↑" : " ↓") : ""}
            </button>
          ))}
        </div>
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search evidence references…"
        />
      </Panel>

      <Panel title={`Evidence (${total})`}>
        {list.loading && <LoadingRow />}
        {!list.loading && rows.length === 0 ? (
          <EmptyRow label="No evidence references match." />
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
