import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  useReactTable, getCoreRowModel, getSortedRowModel, getFilteredRowModel,
  getPaginationRowModel, flexRender, type ColumnDef, type SortingState,
} from '@tanstack/react-table'
import { api } from '../api/client'
import { useProject } from '../project/project'

type Subdomain = {
  id: number; name: string; http_status: number; http_url: string | null
  page_title: string | null; webserver: string | null; content_length: number | null
  is_important: boolean | null; cdn_name: string | null
}

function statusCls(s: number) {
  if (s >= 200 && s < 300) return 'bg-sx-success/20 text-sx-success'
  if (s >= 300 && s < 400) return 'bg-sx-info/20 text-sx-info'
  if (s >= 400 && s < 500) return 'bg-sx-medium/20 text-sx-medium'
  if (s >= 500) return 'bg-sx-critical/20 text-sx-critical'
  return 'bg-sx-surface-2 text-sx-muted'
}

export function Subdomains() {
  const { currentSlug } = useProject()
  const [sorting, setSorting] = useState<SortingState>([{ id: 'name', desc: false }])
  const [globalFilter, setGlobalFilter] = useState('')
  const { data, isLoading, isError } = useQuery({
    queryKey: ['subdomains', currentSlug],
    queryFn: async () => (await api.get<Subdomain[]>('/subdomains/', { params: { project: currentSlug } })).data,
  })

  const columns = useMemo<ColumnDef<Subdomain>[]>(() => [
    { accessorKey: 'name', header: 'Subdomain', cell: (c) => (
        <span>{c.getValue<string>()}{c.row.original.is_important && <span className="ml-2 rounded bg-sx-primary/20 px-1.5 py-0.5 text-xs text-sx-primary">★</span>}</span>) },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>(); return s ? <span className={'rounded px-2 py-0.5 text-xs ' + statusCls(s)}>{s}</span> : <span className="text-sx-muted">—</span> } },
    { accessorKey: 'page_title', header: 'Title', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'webserver', header: 'Web server', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_length', header: 'Length', cell: (c) => c.getValue<number>() || '—' },
    { accessorKey: 'cdn_name', header: 'CDN', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
  ], [])

  const table = useReactTable({
    data: data ?? [], columns, state: { sorting, globalFilter },
    onSortingChange: setSorting, onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  })

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Subdomains</h1>
        <input value={globalFilter} onChange={(e) => setGlobalFilter(e.target.value)} placeholder="Search…"
          className="w-64 rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm outline-none focus:border-sx-primary" />
      </div>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <>
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
            <span>{table.getFilteredRowModel().rows.length} subdomains</span>
            <div className="flex items-center gap-2">
              <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</button>
              <span>Page {table.getState().pagination.pageIndex + 1} / {table.getPageCount() || 1}</span>
              <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
