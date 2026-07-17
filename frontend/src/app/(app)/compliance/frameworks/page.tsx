"use client";

import { useMemo, useState } from "react";
import {
  EmptyRow,
  ErrorRow,
  ForbiddenRow,
  LoadingRow,
  PageHeader,
  Panel,
  SearchInput,
  useAsync,
} from "@/components/cc";
import {
  getConsoleOverview,
  listFrameworks,
  listRequirements,
  type ControlRequirement,
  type FrameworkSummary,
} from "@/lib/compliance";
import { statusLabel } from "@/lib/compliance-helpers";

function FrameworkTree({
  framework,
  validatedCount,
}: {
  framework: FrameworkSummary;
  validatedCount: number;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const limit = 25;

  const reqState = useAsync(
    () =>
      open
        ? listRequirements(framework.key, {
            search: search || undefined,
            limit,
            offset: page * limit,
          })
        : Promise.resolve({
            items: [] as ControlRequirement[],
            total: 0,
            limit,
            offset: 0,
          }),
    [open, framework.key, search, page]
  );

  return (
    <div className="border-b border-gray-800 last:border-0">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-1 py-3 text-left hover:bg-gray-900/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
      >
        <div>
          <div className="text-sm font-semibold text-gray-100">
            {framework.metadata?.name || framework.key}
          </div>
          <div className="text-xs text-gray-500">
            {framework.key} · {framework.status} · {framework.requirement_count}{" "}
            requirements · {validatedCount} validated in org assessments
          </div>
        </div>
        <span className="text-xs text-gray-500">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="mb-4 space-y-3 pl-2">
          <SearchInput
            value={search}
            onChange={(v) => {
              setSearch(v);
              setPage(0);
            }}
            placeholder="Search requirements…"
          />
          {reqState.loading && <LoadingRow label="Loading requirements…" />}
          {reqState.forbidden && <ForbiddenRow />}
          {reqState.error && <ErrorRow message={reqState.error} />}
          {reqState.data && reqState.data.items.length === 0 && (
            <EmptyRow label="No requirements match." />
          )}
          {reqState.data && reqState.data.items.length > 0 && (
            <>
              <ul className="divide-y divide-gray-800 rounded-lg border border-gray-800">
                {reqState.data.items.map((req) => (
                  <li
                    key={req.id}
                    className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm text-gray-200">
                        <span className="font-mono text-xs text-gray-500">
                          {req.requirement_ref}
                        </span>{" "}
                        {req.title}
                      </div>
                      <div className="text-[11px] text-gray-600">
                        {req.domain} · {statusLabel(req.severity)}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span>
                  {reqState.data.total} total · page {page + 1}
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
                    disabled={(page + 1) * limit >= reqState.data.total}
                    onClick={() => setPage((p) => p + 1)}
                    className="rounded border border-gray-800 px-2 py-1 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function FrameworkExplorerPage() {
  const frameworksState = useAsync(() => listFrameworks(), []);
  const overview = useAsync(() => getConsoleOverview(), []);
  const [fwFilter, setFwFilter] = useState("");

  const progressByKey = useMemo(() => {
    const map = new Map<string, number>();
    for (const item of overview.data?.framework_progress ?? []) {
      map.set(item.framework_key, item.validated);
    }
    return map;
  }, [overview.data]);

  if (frameworksState.loading) {
    return (
      <>
        <PageHeader title="Framework Explorer" subtitle="Controls, coverage, hierarchy" />
        <LoadingRow />
      </>
    );
  }
  if (frameworksState.forbidden) {
    return (
      <>
        <PageHeader title="Framework Explorer" />
        <ForbiddenRow />
      </>
    );
  }
  if (frameworksState.error || !frameworksState.data) {
    return (
      <>
        <PageHeader title="Framework Explorer" />
        <ErrorRow message={frameworksState.error ?? "No data"} />
      </>
    );
  }

  const filtered = frameworksState.data.filter((f) => {
    const q = fwFilter.toLowerCase();
    if (!q) return true;
    return (
      f.key.toLowerCase().includes(q) ||
      (f.metadata?.name || "").toLowerCase().includes(q)
    );
  });

  return (
    <>
      <PageHeader
        title="Framework Explorer"
        subtitle="Expand frameworks to browse requirements and assessment coverage"
      />
      <Panel title="Published Frameworks">
        <div className="mb-3">
          <SearchInput
            value={fwFilter}
            onChange={setFwFilter}
            placeholder="Filter frameworks…"
          />
        </div>
        {filtered.length === 0 ? (
          <EmptyRow label="No frameworks available for this organization." />
        ) : (
          filtered.map((fw) => (
            <FrameworkTree
              key={fw.key}
              framework={fw}
              validatedCount={progressByKey.get(fw.key) ?? 0}
            />
          ))
        )}
      </Panel>
    </>
  );
}
