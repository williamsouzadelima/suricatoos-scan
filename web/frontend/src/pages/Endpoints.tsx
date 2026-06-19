import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'

type Endpoint = {
  id: number; http_url: string; http_status: number; page_title: string | null
  content_length: number | null; content_type: string | null; webserver: string | null
}

function statusCls(s: number) {
  if (s >= 200 && s < 300) return 'bg-sx-success/20 text-sx-success'
  if (s >= 300 && s < 400) return 'bg-sx-info/20 text-sx-info'
  if (s >= 400 && s < 500) return 'bg-sx-medium/20 text-sx-medium'
  if (s >= 500) return 'bg-sx-critical/20 text-sx-critical'
  return 'bg-sx-surface-2 text-sx-muted'
}

export function Endpoints() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['endpoints', currentSlug],
    queryFn: async () => (await api.get<Endpoint[]>('/endpoints/', { params: { project: currentSlug } })).data,
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

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Endpoints</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <DataTable data={data} columns={columns} countLabel="endpoints" initialSort={[{ id: 'http_status', desc: true }]} />
      )}
    </div>
  )
}
