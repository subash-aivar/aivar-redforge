"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
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
} from "@/components/cc";
import { listConsoleTimeline } from "@/lib/compliance";

const PAGE_SIZE = 50;

export default function ComplianceTimelinePage() {
  const [kind, setKind] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    setPage(0);
  }, [kind, debouncedQuery]);

  const list = useAsync(
    () =>
      listConsoleTimeline({
        kind: kind ?? undefined,
        search: debouncedQuery || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    [kind, debouncedQuery, page]
  );

  if (list.loading && !list.data) {
    return (
      <>
        <PageHeader title="Compliance Timeline" />
        <LoadingRow />
      </>
    );
  }
  if (list.forbidden) {
    return (
      <>
        <PageHeader title="Compliance Timeline" />
        <ForbiddenRow />
      </>
    );
  }
  if (list.error && !list.data) {
    return (
      <>
        <PageHeader title="Compliance Timeline" />
        <ErrorRow message={list.error} />
      </>
    );
  }

  const events = list.data?.items ?? [];
  const total = list.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Compliance Timeline"
        subtitle="Assessment, recommendation, evidence, and status activity"
      />

      <Panel title="Filters" className="mb-4">
        <div className="mb-3 flex flex-wrap gap-2">
          <FilterChip label="All" active={!kind} onClick={() => setKind(null)} />
          {["assessment", "status", "evidence", "recommendation"].map((k) => (
            <FilterChip
              key={k}
              label={k}
              active={kind === k}
              onClick={() => setKind(k)}
            />
          ))}
        </div>
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search timeline…"
        />
      </Panel>

      <Panel title={`Events (${total})`}>
        {list.loading && <LoadingRow />}
        {!list.loading && events.length === 0 ? (
          <EmptyRow label="No timeline events." />
        ) : (
          !list.loading && (
            <>
              <ol className="relative ml-2 space-y-0 border-l border-gray-800">
                {events.map((ev) => (
                  <li key={ev.id} className="relative pb-4 pl-6">
                    <span className="absolute -left-1.5 top-1.5 h-3 w-3 rounded-full border border-gray-700 bg-gray-900" />
                    <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                          {ev.kind}
                        </div>
                        <div className="text-sm text-gray-200">{ev.title}</div>
                        <div className="text-xs text-gray-500">{ev.detail}</div>
                        {ev.href && (
                          <Link
                            href={ev.href}
                            className="mt-1 inline-block text-[11px] text-red-400 hover:text-red-300"
                          >
                            Open →
                          </Link>
                        )}
                      </div>
                      <time className="shrink-0 text-[11px] tabular-nums text-gray-600">
                        {fmtTime(ev.at)}
                      </time>
                    </div>
                  </li>
                ))}
              </ol>
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
