import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Globe, ExternalLink } from 'lucide-react'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/ui/Badge'
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
    { accessorKey: 'http_url', header: 'URL', cell: (c) => {
        const url = c.getValue<string>()
        return (
          <a href={url} target="_blank" rel="noreferrer"
            className="group inline-flex items-center gap-1.5 font-medium text-sx-text transition-colors hover:text-sx-primary">
            <span className="break-all">{url}</span>
            <ExternalLink size={13} className="shrink-0 text-sx-muted transition-colors group-hover:text-sx-primary" />
          </a>
        )
      } },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>()
        return s
          ? <Badge className={statusCls(s)}><span className="sx-num">{s}</span></Badge>
          : <span className="text-sx-muted">—</span>
      } },
    { accessorKey: 'page_title', header: 'Title', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_type', header: 'Type', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'webserver', header: 'Server', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_length', header: 'Length', cell: (c) => {
        const n = c.getValue<number>()
        return n ? <span className="sx-num text-sx-muted">{n}</span> : <span className="text-sx-muted">—</span>
      } },
  ], [])
  return (
    <DataTable
      data={data ?? []}
      columns={columns}
      countLabel="endpoints"
      loading={isLoading}
      error={isError}
      initialSort={[{ id: 'http_status', desc: true }]}
      emptyIcon={<Globe size={22} />}
      emptyLabel="No endpoints for this scan."
    />
  )
}
