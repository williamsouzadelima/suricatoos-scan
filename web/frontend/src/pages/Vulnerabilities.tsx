import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { ShieldAlert, ExternalLink, ShieldCheck, ShieldX } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'
import { SEVERITY, type SevKey } from '../lib/severity'

type Vuln = {
  id: number; name: string; severity: number; type: string | null
  http_url: string | null; cvss_score: number | null; open_status: boolean | null
  validation_status: string | null
}

// Numeric severity (4=Critical … 0=Info) -> shared SEVERITY metadata, so the
// dot color / text color recolor per identity theme just like the Dashboard.
const SEV_BY_KEY = Object.fromEntries(SEVERITY.map((s) => [s.key, s])) as Record<SevKey, (typeof SEVERITY)[number]>
const SEV_KEY: Record<number, SevKey> = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info' }

const VALID: Record<string, { label: string; cls: string }> = {
  confirmed: { label: 'Confirmed', cls: 'text-sx-success' },
  false_positive: { label: 'False positive', cls: 'text-sx-muted' },
  needs_review: { label: 'Needs review', cls: 'text-sx-medium' },
  error: { label: 'Error', cls: 'text-sx-critical' },
  not_validated: { label: 'Not validated', cls: 'text-sx-info' },
}

export function Vulnerabilities() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['vulnerabilities', currentSlug],
    queryFn: async () => (await api.get<Vuln[]>('/vulnerabilities/', { params: { project: currentSlug } })).data,
  })

  const columns = useMemo<ColumnDef<Vuln>[]>(() => [
    {
      accessorKey: 'severity', header: 'Severity', cell: (c) => {
        const key = SEV_KEY[c.getValue<number>()]
        const s = key ? SEV_BY_KEY[key] : undefined
        if (!s) return <Badge className="text-sx-muted">Unknown</Badge>
        return (
          <Badge className={s.text}>
            <span className="h-2 w-2 rounded-sm" style={{ background: s.cssVar }} />
            {s.label}
          </Badge>
        )
      },
    },
    { accessorKey: 'name', header: 'Name', cell: (c) => <span className="font-medium text-sx-text">{c.getValue<string>()}</span> },
    { accessorKey: 'type', header: 'Type', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    {
      accessorKey: 'http_url', header: 'URL', cell: (c) => {
        const url = c.getValue<string>()
        if (!url) return <span className="text-sx-muted">—</span>
        return (
          <a href={url} target="_blank" rel="noreferrer"
            className="inline-flex items-center gap-1.5 break-all text-sx-muted transition-colors hover:text-sx-primary">
            <span>{url}</span>
            <ExternalLink size={13} className="shrink-0 opacity-70" />
          </a>
        )
      },
    },
    {
      accessorKey: 'cvss_score', header: 'CVSS', cell: (c) => {
        const v = c.getValue<number>()
        return v == null ? <span className="text-sx-muted">—</span> : <span className="sx-num font-semibold">{v}</span>
      },
    },
    {
      accessorKey: 'validation_status', header: 'Validation', cell: (c) => {
        const v = VALID[c.getValue<string>() || 'not_validated'] ?? VALID.not_validated
        return <Badge className={v.cls}>{v.label}</Badge>
      },
    },
    {
      accessorKey: 'open_status', header: 'Status', cell: (c) =>
        c.getValue<boolean>()
          ? <Badge className="text-sx-critical"><ShieldX size={13} />Open</Badge>
          : <Badge className="text-sx-success"><ShieldCheck size={13} />Resolved</Badge>,
    },
  ], [])

  return (
    <div>
      <PageHeader icon={<ShieldAlert size={20} />} title="Vulnerabilities" subtitle="Vulnerabilities found in this project." />
      <DataTable
        data={data ?? []}
        columns={columns}
        countLabel="vulnerabilities"
        initialSort={[{ id: 'severity', desc: true }]}
        loading={isLoading}
        error={isError}
        emptyIcon={<ShieldAlert size={22} />}
        emptyLabel="No vulnerabilities found."
      />
    </div>
  )
}
