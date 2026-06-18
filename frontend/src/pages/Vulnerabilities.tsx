import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  useReactTable, getCoreRowModel, getSortedRowModel, getFilteredRowModel,
  getPaginationRowModel, flexRender, type ColumnDef, type SortingState,
} from '@tanstack/react-table'
import { api } from '../api/client'

type Vuln = {
  id: number; name: string; severity: number; type: string | null
  http_url: string | null; cvss_score: number | null; open_status: boolean | null
  validation_status: string | null
}

const SEV: Record<number, { label: string; cls: string }> = {
  4: { label: 'Critical', cls: 'bg-sx-critical/20 text-sx-critical' },
  3: { label: 'High', cls: 'bg-sx-high/20 text-sx-high' },
  2: { label: 'Medium', cls: 'bg-sx-medium/20 text-sx-medium' },
  1: { label: 'Low', cls: 'bg-sx-low/20 text-sx-low' },
  0: { label: 'Info', cls: 'bg-sx-info/20 text-sx-info' },
  [-1]: { label: 'Unknown', cls: 'bg-sx-surface-2 text-sx-muted' },
}
const VALID: Record<string, { label: string; cls: string }> = {
  confirmed: { label: 'Confirmed', cls: 'bg-sx-success/20 text-sx-success' },
  false_positive: { label: 'False positive', cls: 'bg-sx-surface-2 text-sx-muted' },
  needs_review: { label: 'Needs review', cls: 'bg-sx-medium/20 text-sx-medium' },
  error: { label: 'Error', cls: 'bg-sx-critical/20 text-sx-critical' },
  not_validated: { label: 'Not validated', cls: 'bg-sx-info/15 text-sx-info' },
}

function Badge({ cls, children }: { cls: string; children: React.ReactNode }) {
  return <span className={'rounded px-2 py-0.5 text-xs ' + cls}>{children}</span>
}

export function Vulnerabilities() {
  const [sorting, setSorting] = useState<SortingState>([{ id: 'severity', desc: true }])
  const [globalFilter, setGlobalFilter] = useState('')
  const { data, isLoading, isError } = useQuery({
    queryKey: ['vulnerabilities'],
    queryFn: async () => (await api.get<Vuln[]>('/vulnerabilities/')).data,
  })

  const columns = useMemo<ColumnDef<Vuln>[]>(() => [
    { accessorKey: 'severity', header: 'Severity', cell: (c) => {
        const s = SEV[c.getValue<number>()] ?? SEV[-1]; return <Badge cls={s.cls}>{s.label}</Badge> } },
    { accessorKey: 'name', header: 'Name' },
    { accessorKey: 'type', header: 'Type', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'http_url', header: 'URL', cell: (c) => <span className="break-all text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'cvss_score', header: 'CVSS', cell: (c) => c.getValue<number>() ?? '—' },
    { accessorKey: 'validation_status', header: 'Validation', cell: (c) => {
        const v = VALID[c.getValue<string>() || 'not_validated'] ?? VALID.not_validated; return <Badge cls={v.cls}>{v.label}</Badge> } },
    { accessorKey: 'open_status', header: 'Status', cell: (c) =>
        c.getValue<boolean>() ? <Badge cls="bg-sx-critical/20 text-sx-critical">Open</Badge> : <Badge cls="bg-sx-success/20 text-sx-success">Resolved</Badge> },
  ], [])

  const table = useReactTable({
    data: data ?? [], columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting, onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  })

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Vulnerabilities</h1>
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
                      <td key={cell.id} className="px-4 py-2 align-top">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-between text-sm text-sx-muted">
            <span>{table.getFilteredRowModel().rows.length} findings</span>
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
