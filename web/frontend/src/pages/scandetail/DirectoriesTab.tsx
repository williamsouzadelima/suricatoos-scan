import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { statusCls } from './types'

type Dir = { subdomain_name: string; name: string; http_status: number; length: number; words: number; lines: number }

export function DirectoriesTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-directories', scanId],
    queryFn: async () => (await api.get<Dir[]>('/scan-directories/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Dir>[]>(() => [
    { accessorKey: 'subdomain_name', header: 'Subdomain' },
    { accessorKey: 'name', header: 'Path' },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>(); return s ? <span className={'rounded px-2 py-0.5 text-xs ' + statusCls(s)}>{s}</span> : '—' } },
    { accessorKey: 'length', header: 'Length' },
    { accessorKey: 'words', header: 'Words' },
    { accessorKey: 'lines', header: 'Lines' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load directories.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No directory results for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="paths" initialSort={[{ id: 'subdomain_name', desc: false }]} />
}
