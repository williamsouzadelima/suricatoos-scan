import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Target, Network, Globe, ShieldAlert, Radar, ChevronRight, Activity } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { Card, SectionHeader } from '../components/ui/Card'
import { StatCard } from '../components/ui/StatCard'
import { Donut } from '../components/ui/Donut'
import { Skeleton } from '../components/ui/Skeleton'
import { SEVERITY } from '../lib/severity'

type Stats = {
  targets: number; subdomains: number; subdomains_alive: number
  endpoints: number; endpoints_alive: number; scans: number
  vulnerabilities: { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
}
type Scan = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; subdomain_count: number; vulnerability_count: number
}

const SCAN_STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'text-sx-info' },
  0: { label: 'Failed', cls: 'text-sx-critical' },
  1: { label: 'Running', cls: 'text-sx-medium' },
  2: { label: 'Success', cls: 'text-sx-success' },
  3: { label: 'Aborted', cls: 'text-sx-muted' },
}

function ago(d: string | null) {
  if (!d) return '—'
  const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000)
  if (s < 60) return 'just now'
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function Dashboard() {
  const { currentSlug } = useProject()
  const stats = useQuery({
    queryKey: ['dashboard-stats', currentSlug],
    queryFn: async () => (await api.get<Stats>('/dashboard/stats/', { params: { project: currentSlug } })).data,
  })
  const scans = useQuery({
    queryKey: ['dashboard-recent-scans', currentSlug],
    queryFn: async () => (await api.get<Scan[]>('/scans/', { params: { project: currentSlug } })).data,
    refetchInterval: 8000,
  })

  const v = stats.data?.vulnerabilities
  const donut = SEVERITY.map((s) => ({ label: s.label, value: v?.[s.key] ?? 0, color: s.cssVar }))
  const recent = (scans.data ?? []).slice(0, 6)

  return (
    <div>
      <header className="mb-6">
        <h1 className="sx-uplabel text-2xl font-bold">Dashboard</h1>
        <p className="mt-1 text-sm text-sx-muted">Reconnaissance overview for this project.</p>
      </header>

      {stats.isError && <p className="mb-4 text-sm text-sx-critical">Failed to load stats.</p>}

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.isLoading
          ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[104px]" />)
          : stats.data && (
            <>
              <StatCard icon={<Target size={20} />} label="Targets" value={stats.data.targets} accentText="text-sx-info" />
              <StatCard icon={<Network size={20} />} label="Subdomains" value={stats.data.subdomains}
                sub={`${stats.data.subdomains_alive} alive`} accentText="text-sx-info" />
              <StatCard icon={<Globe size={20} />} label="Endpoints" value={stats.data.endpoints}
                sub={`${stats.data.endpoints_alive} · 200 OK`} accentText="text-sx-info" />
              <StatCard icon={<ShieldAlert size={20} />} label="Vulnerabilities" value={stats.data.vulnerabilities.total}
                sub={`${stats.data.scans} scans`} accentText="text-sx-primary" />
            </>
          )}
      </div>

      {/* Severity chart + recent scans */}
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card accent className="lg:col-span-1">
          <SectionHeader title="Vulnerabilities by severity" icon={<ShieldAlert size={14} />} />
          <div className="flex items-center gap-5 p-5">
            {stats.isLoading ? (
              <Skeleton className="h-[168px] w-[168px] rounded-full" />
            ) : (
              <div className="relative shrink-0">
                <Donut segments={donut} />
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <div className="sx-num text-3xl font-bold leading-none">{v?.total ?? 0}</div>
                  <div className="sx-uplabel text-[10px] text-sx-muted">total</div>
                </div>
              </div>
            )}
            <ul className="flex-1 space-y-1.5">
              {SEVERITY.map((s) => (
                <li key={s.key} className="flex items-center gap-2 text-sm">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.cssVar }} />
                  <span className="text-sx-muted">{s.label}</span>
                  <span className={'sx-num ml-auto font-semibold ' + s.text}>{v?.[s.key] ?? 0}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card accent className="lg:col-span-2">
          <SectionHeader
            title="Recent scans"
            icon={<Radar size={14} />}
            action={<Link to="/scans" className="flex items-center gap-1 text-xs text-sx-primary hover:underline">View all <ChevronRight size={13} /></Link>}
          />
          {scans.isLoading ? (
            <div className="space-y-2 p-4">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
          ) : recent.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-4 py-12 text-center text-sx-muted">
              <Activity size={22} className="opacity-60" />
              <p className="text-sm">No scans yet.</p>
              <Link to="/scans" className="text-sm text-sx-primary hover:underline">Start your first scan →</Link>
            </div>
          ) : (
            <ul className="divide-y divide-sx-border">
              {recent.map((s) => {
                const st = SCAN_STATUS[s.scan_status] ?? SCAN_STATUS[-1]
                return (
                  <li key={s.id}>
                    <Link to={`/scans/${s.id}`} className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-sx-surface-2">
                      <span className={'h-2 w-2 shrink-0 rounded-full bg-current ' + st.cls} />
                      <span className="min-w-0 flex-1 truncate font-medium text-sx-text">{s.domain_name}</span>
                      <span className="hidden text-xs text-sx-muted sm:inline">{s.engine_name}</span>
                      <span className={'sx-badge px-2 py-0.5 text-xs ' + st.cls}>{st.label}</span>
                      <span className="w-16 text-right text-xs text-sx-muted">{ago(s.start_scan_date)}</span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          )}
        </Card>
      </div>
    </div>
  )
}
