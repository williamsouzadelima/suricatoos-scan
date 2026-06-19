import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Eye, ScanSearch, ShieldAlert, Tag, ExternalLink } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/ui/PageHeader'
import { Card, SectionHeader } from '../components/ui/Card'
import { StatCard } from '../components/ui/StatCard'
import { Badge } from '../components/ui/Badge'
import { Skeleton } from '../components/ui/Skeleton'

type OsintResult = { id: number; bucket: string; event_type: string; data: string; is_malicious: boolean }

const BUCKET_LABEL: Record<string, string> = {
  malicious: 'Malicious / Blacklisted', code_repos: 'Public Code Repos',
  infra_dns: 'DNS & Email', netblock_asn: 'Netblock / ASN', affiliates: 'Affiliates',
  cohosted: 'Co-Hosted', geo: 'Geolocation', web_tech: 'Web Tech',
}

function isUrl(v: string) {
  return /^https?:\/\//i.test(v.trim())
}

export function Osint() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['osint', currentSlug],
    queryFn: async () => (await api.get<OsintResult[]>('/listOsintResults/', { params: { project: currentSlug } })).data,
  })

  const rows = data ?? []
  const total = rows.length
  const maliciousCount = rows.filter((o) => o.is_malicious).length
  const bucketCount = new Set(rows.map((o) => o.bucket)).size

  const columns = useMemo<ColumnDef<OsintResult>[]>(() => [
    { accessorKey: 'bucket', header: 'Category', cell: (c) => {
        const o = c.row.original
        return (
          <Badge className={o.is_malicious ? 'text-sx-critical' : 'text-sx-muted'}>
            {o.is_malicious && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
            {BUCKET_LABEL[o.bucket] ?? o.bucket}
          </Badge>
        )
      } },
    { accessorKey: 'event_type', header: 'Type', cell: (c) => {
        const v = c.getValue<string>()
        return v ? <span className="text-sx-muted">{v}</span> : <span className="text-sx-muted">—</span>
      } },
    { accessorKey: 'data', header: 'Data', cell: (c) => {
        const v = c.getValue<string>()
        if (!v) return <span className="text-sx-muted">—</span>
        if (isUrl(v)) {
          return (
            <a href={v} target="_blank" rel="noreferrer"
              className="group inline-flex items-center gap-1.5 text-sx-text transition-colors hover:text-sx-primary">
              <span className="break-all">{v}</span>
              <ExternalLink size={13} className="shrink-0 transition-colors group-hover:text-sx-primary" />
            </a>
          )
        }
        return <span className="break-all text-sx-text">{v}</span>
      } },
  ], [])

  return (
    <div>
      <PageHeader
        icon={<Eye size={20} />}
        title="OSINT Intelligence"
        subtitle="Open-source intelligence findings."
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-[104px]" />)
          : (
            <>
              <StatCard icon={<ScanSearch size={20} />} label="Findings" value={total} accentText="text-sx-info" />
              <StatCard icon={<ShieldAlert size={20} />} label="Malicious" value={maliciousCount}
                sub={total > 0 ? `${Math.round((maliciousCount / total) * 100)}% flagged` : undefined}
                accentText={maliciousCount > 0 ? 'text-sx-critical' : 'text-sx-text'} />
              <StatCard icon={<Tag size={20} />} label="Categories" value={bucketCount} accentText="text-sx-info" />
            </>
          )}
      </div>

      <Card accent>
        <SectionHeader title="Intelligence findings" icon={<Eye size={14} />} />
        <div className="p-4">
          <DataTable
            data={rows}
            columns={columns}
            countLabel="findings"
            loading={isLoading}
            error={isError}
            initialSort={[{ id: 'bucket', desc: false }]}
            searchPlaceholder="Search findings…"
            emptyIcon={<ScanSearch size={22} />}
            emptyLabel="No OSINT results."
          />
        </div>
      </Card>
    </div>
  )
}
