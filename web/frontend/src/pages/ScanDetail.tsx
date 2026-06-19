import { useQuery } from '@tanstack/react-query'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import { type ComponentType } from 'react'
import {
  Crosshair, ChevronLeft, LayoutDashboard, Globe, Network,
  Image, FolderTree, Cpu, type LucideProps,
} from 'lucide-react'
import { api } from '../api/client'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'
import { Skeleton } from '../components/ui/Skeleton'
import { type ScanDetail as ScanDetailT, STATUS } from './scandetail/types'
import { OverviewTab } from './scandetail/OverviewTab'
import { EndpointsTab } from './scandetail/EndpointsTab'
import { IpsTab } from './scandetail/IpsTab'
import { ScreenshotsTab } from './scandetail/ScreenshotsTab'
import { DirectoriesTab } from './scandetail/DirectoriesTab'
import { TechTab } from './scandetail/TechTab'

const TABS = ['overview', 'endpoints', 'ips', 'screenshots', 'directories', 'tech'] as const
type Tab = typeof TABS[number]
const TAB_META: Record<Tab, { label: string; icon: ComponentType<LucideProps> }> = {
  overview: { label: 'Overview', icon: LayoutDashboard },
  endpoints: { label: 'Endpoints', icon: Globe },
  ips: { label: 'Ports & IPs', icon: Network },
  screenshots: { label: 'Screenshots', icon: Image },
  directories: { label: 'Directories', icon: FolderTree },
  tech: { label: 'Tech', icon: Cpu },
}

export function ScanDetail() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const active = (TABS.includes(params.get('tab') as Tab) ? params.get('tab') : 'overview') as Tab
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => (await api.get<ScanDetailT>(`/scans/${id}/`)).data,
    refetchInterval: (q) => (q.state.data?.scan_status === 1 ? 5000 : false),
  })

  if (isLoading) {
    return (
      <div>
        <Link to="/scans" className="mb-4 inline-flex items-center gap-1 text-sm text-sx-muted transition-colors hover:text-sx-text">
          <ChevronLeft size={15} /> Scans
        </Link>
        <div className="mb-6 flex items-center gap-3">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-56" />
            <Skeleton className="h-3 w-32" />
          </div>
        </div>
        <Skeleton className="h-10 w-full max-w-2xl rounded-xl" />
      </div>
    )
  }
  if (isError || !data) {
    return (
      <div>
        <Link to="/scans" className="mb-4 inline-flex items-center gap-1 text-sm text-sx-muted transition-colors hover:text-sx-text">
          <ChevronLeft size={15} /> Scans
        </Link>
        <p className="text-sm text-sx-critical">Failed to load scan.</p>
      </div>
    )
  }

  const st = STATUS[data.scan_status] ?? STATUS[-1]
  const scanId = Number(id)

  return (
    <div>
      <Link to="/scans" className="mb-4 inline-flex items-center gap-1 text-sm text-sx-muted transition-colors hover:text-sx-text">
        <ChevronLeft size={15} /> Scans
      </Link>

      <PageHeader
        icon={<Crosshair size={20} />}
        title={data.domain_name}
        subtitle={data.engine_name}
        actions={<Badge className={st.cls}>{st.label}</Badge>}
      />

      {/* Segmented tab control */}
      <div className="mb-6 flex flex-wrap gap-1.5">
        {TABS.map((t) => {
          const { label, icon: Icon } = TAB_META[t]
          const isActive = active === t
          return (
            <button
              key={t}
              onClick={() => setParams(t === 'overview' ? {} : { tab: t }, { replace: true })}
              className={
                'sx-uplabel flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors ' +
                (isActive
                  ? 'border-sx-primary/40 bg-sx-primary/10 text-sx-primary'
                  : 'border-transparent text-sx-muted hover:bg-sx-surface-2 hover:text-sx-text')
              }
            >
              <Icon size={15} />
              {label}
            </button>
          )
        })}
      </div>

      {active === 'overview' && <OverviewTab data={data} />}
      {active === 'endpoints' && <EndpointsTab scanId={scanId} />}
      {active === 'ips' && <IpsTab scanId={scanId} />}
      {active === 'screenshots' && <ScreenshotsTab scanId={scanId} />}
      {active === 'directories' && <DirectoriesTab scanId={scanId} />}
      {active === 'tech' && <TechTab scanId={scanId} />}
    </div>
  )
}
