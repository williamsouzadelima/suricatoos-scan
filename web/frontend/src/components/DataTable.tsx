import { useMemo, useState, type ReactNode } from 'react'
import {
  useReactTable, getCoreRowModel, getSortedRowModel, getFilteredRowModel,
  getPaginationRowModel, flexRender, type ColumnDef, type SortingState,
} from '@tanstack/react-table'
import { Search, ArrowUp, ArrowDown, ChevronsUpDown, ChevronLeft, ChevronRight, Inbox } from 'lucide-react'
import { Skeleton } from './ui/Skeleton'
import { EmptyState } from './ui/EmptyState'

export function DataTable<T>({
  data, columns, countLabel, initialSort = [], pageSize = 25,
  loading = false, error = false, toolbar, searchPlaceholder = 'Search…',
  emptyIcon, emptyLabel,
}: {
  data: T[]
  columns: ColumnDef<T>[]
  countLabel: string
  initialSort?: SortingState
  pageSize?: number
  /** Show skeleton rows instead of data (lets the page delegate its loading UI). */
  loading?: boolean
  /** Show an inline error instead of an empty state. */
  error?: boolean
  /** Extra controls (filters, actions) rendered left of the search box. */
  toolbar?: ReactNode
  searchPlaceholder?: string
  emptyIcon?: ReactNode
  emptyLabel?: string
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort)
  const [globalFilter, setGlobalFilter] = useState('')
  const cols = useMemo(() => columns, [columns])
  const table = useReactTable({
    data, columns: cols, state: { sorting, globalFilter },
    onSortingChange: setSorting, onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  })

  const rows = table.getRowModel().rows
  const filteredCount = table.getFilteredRowModel().rows.length

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {toolbar}
        <div className="relative ml-auto">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sx-muted" />
          <input value={globalFilter} onChange={(e) => setGlobalFilter(e.target.value)} placeholder={searchPlaceholder}
            className="w-56 rounded-lg border border-sx-border bg-sx-surface-2 py-1.5 pl-9 pr-3 text-sm outline-none transition-colors focus:border-sx-primary sm:w-64" />
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-sx-border">
        <table className="w-full text-sm">
          <thead className="bg-sx-surface-2 text-left text-sx-muted">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => {
                  const sorted = h.column.getIsSorted()
                  const canSort = h.column.getCanSort()
                  return (
                    <th key={h.id} className="sx-uplabel px-4 py-2.5 text-[11px] font-semibold">
                      <button type="button" disabled={!canSort} onClick={h.column.getToggleSortingHandler()}
                        className={'flex select-none items-center gap-1 ' + (canSort ? 'cursor-pointer hover:text-sx-text' : 'cursor-default')}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {canSort && (sorted === 'asc'
                          ? <ArrowUp size={12} />
                          : sorted === 'desc'
                          ? <ArrowDown size={12} />
                          : <ChevronsUpDown size={12} className="opacity-30" />)}
                      </button>
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {loading
              ? Array.from({ length: 8 }).map((_, i) => (
                <tr key={'sk' + i} className="border-t border-sx-border">
                  {cols.map((_, j) => <td key={j} className="px-4 py-2.5"><Skeleton className="h-4" /></td>)}
                </tr>
              ))
              : rows.map((row) => (
                <tr key={row.id} className="border-t border-sx-border transition-colors hover:bg-sx-surface-2/60">
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="break-all px-4 py-2.5 align-top">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>

        {!loading && error && (
          <div className="px-4 py-10 text-center text-sm text-sx-critical">Failed to load {countLabel}.</div>
        )}
        {!loading && !error && rows.length === 0 && (
          <EmptyState icon={emptyIcon ?? <Inbox size={22} />} title={emptyLabel ?? `No ${countLabel} found.`} />
        )}
      </div>

      <div className="mt-3 flex items-center justify-between text-sm text-sx-muted">
        <span>{filteredCount} {countLabel}</span>
        <div className="flex items-center gap-2">
          <button aria-label="Previous page" className="flex items-center rounded border border-sx-border px-2 py-1 hover:text-sx-text disabled:opacity-40"
            onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}><ChevronLeft size={14} /></button>
          <span>Page {table.getState().pagination.pageIndex + 1} / {table.getPageCount() || 1}</span>
          <button aria-label="Next page" className="flex items-center rounded border border-sx-border px-2 py-1 hover:text-sx-text disabled:opacity-40"
            onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}><ChevronRight size={14} /></button>
        </div>
      </div>
    </div>
  )
}
