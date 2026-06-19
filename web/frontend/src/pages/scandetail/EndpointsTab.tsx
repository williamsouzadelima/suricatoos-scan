import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { statusCls } from './types'

type Endpoint = {
  id: number; http_url: string; http_status: number; page_title: string | null
  content_length: number | null; content_type: string | null; webserver: string | null
  response_time: number | null
}

export function EndpointsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-endpoints', scanId],
    queryFn: async () => (await api.get<Endpoint[]>('/endpoints/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Endpoint>[]>(() => [
    { accessorKey: 'http_url', header: 'URL' },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>(); return s ? <span className={'rounded px-2 py-0.5 text-xs ' + statusCls(s)}>{s}</span> : <span className="text-sx-muted">—</span> } },
    { accessorKey: 'page_title', header: 'Title', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_type', header: 'Type', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'webserver', header: 'Server', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_length', header: 'Length', cell: (c) => c.getValue<number>() || '—' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load endpoints.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No endpoints for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="endpoints" initialSort={[{ id: 'http_status', desc: true }]} />
}
