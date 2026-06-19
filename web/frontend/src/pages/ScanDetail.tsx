import { useQuery } from '@tanstack/react-query'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import { api } from '../api/client'
import { type ScanDetail as ScanDetailT, STATUS } from './scandetail/types'
import { OverviewTab } from './scandetail/OverviewTab'
import { EndpointsTab } from './scandetail/EndpointsTab'
import { IpsTab } from './scandetail/IpsTab'
import { ScreenshotsTab } from './scandetail/ScreenshotsTab'
import { DirectoriesTab } from './scandetail/DirectoriesTab'
import { TechTab } from './scandetail/TechTab'

const TABS = ['overview', 'endpoints', 'ips', 'screenshots', 'directories', 'tech'] as const
type Tab = typeof TABS[number]
const TAB_LABEL: Record<Tab, string> = {
  overview: 'Overview', endpoints: 'Endpoints', ips: 'Ports & IPs',
  screenshots: 'Screenshots', directories: 'Directories', tech: 'Tech',
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
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError || !data) return <p className="text-sx-critical">Failed to load scan.</p>
  const st = STATUS[data.scan_status] ?? STATUS[-1]
  const scanId = Number(id)
  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <Link to="/scans" className="text-sm text-sx-muted hover:text-sx-text">← Scans</Link>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{data.domain_name}</h1>
        <span className="text-sx-muted">{data.engine_name}</span>
        <span className={'rounded px-2 py-0.5 text-xs ' + st.cls}>{st.label}</span>
      </div>
      <div className="mb-6 flex gap-1 border-b border-sx-border">
        {TABS.map((t) => (
          <button key={t} onClick={() => setParams(t === 'overview' ? {} : { tab: t }, { replace: true })}
            className={'px-3 py-2 text-sm ' + (active === t ? 'border-b-2 border-sx-primary text-sx-text' : 'text-sx-muted hover:text-sx-text')}>
            {TAB_LABEL[t]}
          </button>
        ))}
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
