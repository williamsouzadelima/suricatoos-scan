import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Globe, ExternalLink } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'

type Endpoint = {
  id: number; http_url: string; http_status: number; page_title: string | null
  content_length: number | null; content_type: string | null; webserver: string | null
}

function statusCls(s: number) {
  if (s >= 200 && s < 300) return 'text-sx-success'
  if (s >= 300 && s < 400) return 'text-sx-info'
  if (s >= 400 && s < 500) return 'text-sx-medium'
  if (s >= 500) return 'text-sx-critical'
  return 'text-sx-muted'
}

export function Endpoints() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['endpoints', currentSlug],
    queryFn: async () => (await api.get<Endpoint[]>('/endpoints/', { params: { project: currentSlug } })).data,
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
    <div>
      <PageHeader icon={<Globe size={20} />} title="Endpoints" subtitle="HTTP endpoints discovered in this project." />
      <DataTable
        data={data ?? []}
        columns={columns}
        countLabel="endpoints"
        loading={isLoading}
        error={isError}
        initialSort={[{ id: 'http_status', desc: true }]}
        emptyIcon={<Globe size={22} />}
        emptyLabel="No endpoints discovered yet."
      />
    </div>
  )
}
