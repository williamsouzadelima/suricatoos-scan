import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'

type Secret = {
  id: number; source: string | null; rule_id: string | null; file_path: string | null
  repo_url: string | null; line: number | null; secret_redacted: string | null
  description: string | null; severity: number; discovered_date: string | null
}

const SEV: Record<number, { label: string; cls: string }> = {
  4: { label: 'Critical', cls: 'bg-sx-critical/20 text-sx-critical' },
  3: { label: 'High', cls: 'bg-sx-high/20 text-sx-high' },
  2: { label: 'Medium', cls: 'bg-sx-medium/20 text-sx-medium' },
  1: { label: 'Low', cls: 'bg-sx-low/20 text-sx-low' },
  0: { label: 'Info', cls: 'bg-sx-info/20 text-sx-info' },
  [-1]: { label: 'Unknown', cls: 'bg-sx-surface-2 text-sx-muted' },
}

export function LeakedSecrets() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['secrets', currentSlug],
    queryFn: async () => (await api.get<Secret[]>('/secrets/', { params: { project: currentSlug } })).data,
  })

  const columns = useMemo<ColumnDef<Secret>[]>(() => [
    { accessorKey: 'severity', header: 'Severity', cell: (c) => {
        const s = SEV[c.getValue<number>()] ?? SEV[-1]; return <span className={'rounded px-2 py-0.5 text-xs ' + s.cls}>{s.label}</span> } },
    { accessorKey: 'rule_id', header: 'Rule', cell: (c) => c.getValue<string>() || '—' },
    { accessorKey: 'source', header: 'Source', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { id: 'location', header: 'Location', cell: (c) => {
        const r = c.row.original; const loc = r.file_path || r.repo_url || '—'
        return <span className="break-all text-sx-muted">{loc}{r.line ? `:${r.line}` : ''}</span> } },
    { accessorKey: 'secret_redacted', header: 'Secret (masked)', cell: (c) => <code className="break-all text-xs text-sx-text">{c.getValue<string>() || '—'}</code> },
    { accessorKey: 'description', header: 'Description', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
  ], [])

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Leaked Secrets</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <DataTable data={data} columns={columns} countLabel="secrets" initialSort={[{ id: 'severity', desc: true }]} />
      )}
    </div>
  )
}
