import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'

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

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Subdomains</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <DataTable data={data} columns={columns} countLabel="subdomains" initialSort={[{ id: 'name', desc: false }]} />
      )}
    </div>
  )
}
