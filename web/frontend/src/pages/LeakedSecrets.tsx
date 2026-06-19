import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { KeyRound, ExternalLink, Copy, Check, FileCode } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'

type Secret = {
  id: number; source: string | null; rule_id: string | null; file_path: string | null
  repo_url: string | null; line: number | null; secret_redacted: string | null
  description: string | null; severity: number; discovered_date: string | null
}

const SEV: Record<number, { label: string; text: string; cssVar: string }> = {
  4: { label: 'Critical', text: 'text-sx-critical', cssVar: 'var(--sx-critical)' },
  3: { label: 'High', text: 'text-sx-high', cssVar: 'var(--sx-high)' },
  2: { label: 'Medium', text: 'text-sx-medium', cssVar: 'var(--sx-medium)' },
  1: { label: 'Low', text: 'text-sx-low', cssVar: 'var(--sx-low)' },
  0: { label: 'Info', text: 'text-sx-info', cssVar: 'var(--sx-info)' },
  [-1]: { label: 'Unknown', text: 'text-sx-muted', cssVar: 'var(--sx-muted)' },
}

function CopySecret({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      title="Copy masked secret"
      aria-label="Copy masked secret"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          /* clipboard unavailable — no-op */
        }
      }}
      className="shrink-0 rounded p-1 text-sx-muted opacity-0 transition-colors hover:text-sx-primary group-hover:opacity-100"
    >
      {copied ? <Check size={13} className="text-sx-success" /> : <Copy size={13} />}
    </button>
  )
}

export function LeakedSecrets() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['secrets', currentSlug],
    queryFn: async () => (await api.get<Secret[]>('/secrets/', { params: { project: currentSlug } })).data,
  })

  const columns = useMemo<ColumnDef<Secret>[]>(() => [
    { accessorKey: 'severity', header: 'Severity', cell: (c) => {
        const s = SEV[c.getValue<number>()] ?? SEV[-1]
        return (
          <Badge className={s.text}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.cssVar }} />
            {s.label}
          </Badge>
        )
      } },
    { accessorKey: 'rule_id', header: 'Rule', cell: (c) => {
        const v = c.getValue<string>()
        return v ? <span className="font-medium text-sx-text">{v}</span> : <span className="text-sx-muted">—</span>
      } },
    { accessorKey: 'source', header: 'Source', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { id: 'location', header: 'Location', cell: (c) => {
        const r = c.row.original
        const loc = r.file_path || r.repo_url || '—'
        const suffix = r.line ? `:${r.line}` : ''
        if (r.repo_url && !r.file_path) {
          return (
            <a href={r.repo_url} target="_blank" rel="noreferrer"
              className="group inline-flex items-center gap-1.5 text-sx-muted transition-colors hover:text-sx-primary">
              <span className="break-all">{loc}{suffix}</span>
              <ExternalLink size={13} className="shrink-0 transition-colors group-hover:text-sx-primary" />
            </a>
          )
        }
        if (loc === '—') return <span className="text-sx-muted">—</span>
        return (
          <span className="inline-flex items-center gap-1.5 text-sx-muted">
            <FileCode size={13} className="shrink-0 opacity-60" />
            <span className="break-all">{loc}{suffix}</span>
          </span>
        )
      } },
    { accessorKey: 'secret_redacted', header: 'Secret (masked)', cell: (c) => {
        const v = c.getValue<string>()
        if (!v) return <span className="text-sx-muted">—</span>
        return (
          <span className="group inline-flex items-center gap-1.5">
            <code className="break-all text-xs text-sx-text">{v}</code>
            <CopySecret value={v} />
          </span>
        )
      } },
    { accessorKey: 'description', header: 'Description', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
  ], [])

  return (
    <div>
      <PageHeader
        icon={<KeyRound size={20} />}
        title="Secrets"
        subtitle="Secrets and credentials exposed in this project."
      />
      <DataTable
        data={data ?? []}
        columns={columns}
        countLabel="secrets"
        loading={isLoading}
        error={isError}
        initialSort={[{ id: 'severity', desc: true }]}
        emptyIcon={<KeyRound size={22} />}
        emptyLabel="No leaked secrets found."
      />
    </div>
  )
}
