"use client";

import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-react";
import { useState } from "react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState, LoadingState } from "@/design-system/primitives/States";

export interface TableViewModel<TRow> {
  id: string;
  title: string;
  columns: ColumnDef<TRow, unknown>[];
  rows: TRow[];
  isLoading?: boolean;
  emptyMessage?: string;
  pageSize?: number;
}

/** Reusable TanStack Table widget — the single place `@tanstack/
 * react-table` is wired up. Headless by design: this widget only
 * supplies the dark-theme table chrome; column definitions and data
 * always come from the dashboard aggregation layer. */
export function TableWidget<TRow>({
  title,
  columns,
  rows,
  isLoading,
  emptyMessage = "No rows to display.",
  pageSize = 10,
}: TableViewModel<TRow>) {
  const [sorting, setSorting] = useState<SortingState>([]);

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {isLoading ? (
          <LoadingState />
        ) : rows.length === 0 ? (
          <EmptyState message={emptyMessage} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id} className="border-b border-gray-800">
                    {headerGroup.headers.map((header) => {
                      const sortState = header.column.getIsSorted();
                      return (
                        <th
                          key={header.id}
                          className="cursor-pointer select-none px-2 py-2 text-xs font-semibold uppercase tracking-wider text-gray-500"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <span className="inline-flex items-center gap-1">
                            {header.isPlaceholder
                              ? null
                              : flexRender(header.column.columnDef.header, header.getContext())}
                            {header.column.getCanSort() &&
                              (sortState === "asc" ? (
                                <ChevronUp className="h-3 w-3" aria-hidden="true" />
                              ) : sortState === "desc" ? (
                                <ChevronDown className="h-3 w-3" aria-hidden="true" />
                              ) : (
                                <ChevronsUpDown className="h-3 w-3 opacity-40" aria-hidden="true" />
                              ))}
                          </span>
                        </th>
                      );
                    })}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr key={row.id} className="border-b border-gray-900 hover:bg-gray-800/40">
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-2 py-2 text-gray-300">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {table.getPageCount() > 1 && (
              <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
                <span>
                  Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={!table.getCanPreviousPage()}
                    onClick={() => table.previousPage()}
                    className="rounded border border-gray-800 px-2 py-1 disabled:opacity-30"
                  >
                    Prev
                  </button>
                  <button
                    type="button"
                    disabled={!table.getCanNextPage()}
                    onClick={() => table.nextPage()}
                    className="rounded border border-gray-800 px-2 py-1 disabled:opacity-30"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
