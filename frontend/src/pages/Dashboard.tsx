import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'

type Stats = {
  targets: number; subdomains: number; subdomains_alive: number
  endpoints: number; endpoints_alive: number; scans: number
  vulnerabilities: { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
}

function Card({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div className="rounded-xl border border-sx-border bg-sx-surface p-4">
      <div className="text-sm text-sx-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-sx-muted">{sub}</div>}
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
      <h1 className="mb-5 text-xl font-semibold">Dashboard</h1>
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load stats.</p>}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card label="Targets" value={data.targets} />
            <Card label="Subdomains" value={data.subdomains} sub={`${data.subdomains_alive} alive`} />
            <Card label="Endpoints" value={data.endpoints} sub={`${data.endpoints_alive} (200 OK)`} />
            <Card label="Vulnerabilities" value={data.vulnerabilities.total} sub={`${data.scans} scans`} />
          </div>
          <h2 className="mb-3 mt-8 text-base font-medium">Vulnerabilities by severity</h2>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {SEV.map((s) => (
              <div key={s.key} className="rounded-xl border border-sx-border bg-sx-surface p-4 text-center">
                <div className={'text-2xl font-bold ' + s.cls}>{data.vulnerabilities[s.key]}</div>
                <div className="mt-1 text-xs text-sx-muted">{s.label}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
