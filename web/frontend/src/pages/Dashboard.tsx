import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'

type Stats = {
  targets: number; subdomains: number; subdomains_alive: number
  endpoints: number; endpoints_alive: number; scans: number
  vulnerabilities: { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
}

function Card({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: string }) {
  return (
    <div className="sx-accent overflow-hidden rounded-xl border border-sx-border bg-sx-surface p-4">
      <div className={'sx-num text-3xl font-bold leading-none ' + (accent ?? 'text-sx-info')}>{value}</div>
      <div className="sx-uplabel mt-2 text-[11px] text-sx-muted">{label}</div>
      {sub && <div className="mt-1 text-xs text-sx-muted">{sub}</div>}
    </div>
  )
}

const SEV: { key: keyof Stats['vulnerabilities']; label: string; cls: string }[] = [
  { key: 'critical', label: 'Critical', cls: 'text-sx-critical' },
  { key: 'high', label: 'High', cls: 'text-sx-high' },
  { key: 'medium', label: 'Medium', cls: 'text-sx-medium' },
  { key: 'low', label: 'Low', cls: 'text-sx-low' },
  { key: 'info', label: 'Info', cls: 'text-sx-info' },
]

export function Dashboard() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['dashboard-stats', currentSlug],
    queryFn: async () => (await api.get<Stats>('/dashboard/stats/', { params: { project: currentSlug } })).data,
  })

  return (
    <div>
      <h1 className="sx-uplabel mb-5 text-xl font-bold">Dashboard</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load stats.</p>}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card label="Targets" value={data.targets} />
            <Card label="Subdomains" value={data.subdomains} sub={`${data.subdomains_alive} alive`} />
            <Card label="Endpoints" value={data.endpoints} sub={`${data.endpoints_alive} (200 OK)`} />
            <Card label="Vulnerabilities" value={data.vulnerabilities.total} sub={`${data.scans} scans`} accent="text-sx-primary" />
          </div>
          <h2 className="sx-uplabel mb-3 mt-8 text-sm font-semibold text-sx-muted">Vulnerabilities by severity</h2>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {SEV.map((s) => (
              <div key={s.key} className="rounded-xl border border-sx-border bg-sx-surface p-4 text-center">
                <div className={'sx-num text-2xl font-bold ' + s.cls}>{data.vulnerabilities[s.key]}</div>
                <div className="sx-uplabel mt-1 text-[11px] text-sx-muted">{s.label}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
