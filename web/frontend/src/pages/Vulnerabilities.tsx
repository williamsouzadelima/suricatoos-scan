import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'

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
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['vulnerabilities', currentSlug],
    queryFn: async () => (await api.get<Vuln[]>('/vulnerabilities/', { params: { project: currentSlug } })).data,
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

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Vulnerabilities</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <DataTable data={data} columns={columns} countLabel="vulnerabilities" initialSort={[{ id: 'severity', desc: true }]} />
      )}
    </div>
  )
}
