import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Network, Star, ExternalLink } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'

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
    { accessorKey: 'name', header: 'Subdomain', cell: (c) => {
        const url = c.row.original.http_url
        return (
          <span className="flex items-center gap-1.5">
            {c.row.original.is_important && (
              <Star size={13} className="shrink-0 fill-sx-primary text-sx-primary" aria-label="Important" />
            )}
            {url ? (
              <a href={url} target="_blank" rel="noreferrer"
                className="inline-flex items-center gap-1 font-medium text-sx-text transition-colors hover:text-sx-primary">
                {c.getValue<string>()}
                <ExternalLink size={12} className="shrink-0 text-sx-muted" />
              </a>
            ) : (
              <span className="font-medium text-sx-text">{c.getValue<string>()}</span>
            )}
          </span>
        )
      } },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>()
        return s ? <Badge className={statusCls(s)}>{s}</Badge> : <span className="text-sx-muted">—</span> } },
    { accessorKey: 'page_title', header: 'Title', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'webserver', header: 'Web server', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_length', header: 'Length', cell: (c) => <span className="sx-num text-sx-muted">{c.getValue<number>() || '—'}</span> },
    { accessorKey: 'cdn_name', header: 'CDN', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
  ], [])

  return (
    <div>
      <PageHeader
        icon={<Network size={20} />}
        title="Subdomains"
        subtitle="Subdomains discovered in this project."
      />
      <DataTable
        data={data ?? []}
        columns={columns}
        countLabel="subdomains"
        initialSort={[{ id: 'name', desc: false }]}
        loading={isLoading}
        error={isError}
        emptyIcon={<Network size={22} />}
        emptyLabel="No subdomains discovered yet."
      />
    </div>
  )
}
