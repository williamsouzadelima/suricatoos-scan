import { useMemo, useState } from 'react'
import {
  useReactTable, getCoreRowModel, getSortedRowModel, getFilteredRowModel,
  getPaginationRowModel, flexRender, type ColumnDef, type SortingState,
} from '@tanstack/react-table'

export function DataTable<T>({ data, columns, countLabel, initialSort = [], pageSize = 25 }: {
  data: T[]; columns: ColumnDef<T>[]; countLabel: string
  initialSort?: SortingState; pageSize?: number
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
  return (
    <div>
      <div className="mb-3 flex justify-end">
        <input value={globalFilter} onChange={(e) => setGlobalFilter(e.target.value)} placeholder="Search…"
          className="w-64 rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm outline-none focus:border-sx-primary" />
      </div>
      <div className="overflow-x-auto rounded-xl border border-sx-border">
        <table className="w-full text-sm">
          <thead className="bg-sx-surface-2 text-left text-sx-muted">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="cursor-pointer select-none px-4 py-2" onClick={h.column.getToggleSortingHandler()}>
                    {flexRender(h.column.columnDef.header, h.getContext())}
                    {{ asc: ' ↑', desc: ' ↓' }[h.column.getIsSorted() as string] ?? ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="border-t border-sx-border">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-2 align-top break-all">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex items-center justify-between text-sm text-sx-muted">
        <span>{table.getFilteredRowModel().rows.length} {countLabel}</span>
        <div className="flex items-center gap-2">
          <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</button>
          <span>Page {table.getState().pagination.pageIndex + 1} / {table.getPageCount() || 1}</span>
          <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</button>
        </div>
      </div>
    </div>
  )
}
