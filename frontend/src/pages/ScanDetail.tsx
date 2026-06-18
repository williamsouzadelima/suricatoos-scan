import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { api } from '../api/client'

type Activity = { id: number; title: string; name: string; status: number; time: string | null; error_message: string | null }
type ScanDetail = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; stop_scan_date: string | null
  subdomain_count: number; endpoint_count: number; vulnerability_count: number
  osint_count: number; progress: number; activities: Activity[]
}

const STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'bg-sx-info/20 text-sx-info' },
  0: { label: 'Failed', cls: 'bg-sx-critical/20 text-sx-critical' },
  1: { label: 'Running', cls: 'bg-sx-medium/20 text-sx-medium' },
  2: { label: 'Success', cls: 'bg-sx-success/20 text-sx-success' },
  3: { label: 'Aborted', cls: 'bg-sx-surface-2 text-sx-muted' },
}
function fmt(d: string | null) { return d ? new Date(d).toLocaleString() : '—' }

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-sx-border bg-sx-surface p-4">
      <div className="text-sm text-sx-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  )
}

export function ScanDetail() {
  const { id } = useParams()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => (await api.get<ScanDetail>(`/scans/${id}/`)).data,
    refetchInterval: (q) => (q.state.data?.scan_status === 1 ? 5000 : false),
  })

  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError || !data) return <p className="text-sx-critical">Failed to load scan.</p>
  const st = STATUS[data.scan_status] ?? STATUS[-1]

  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <Link to="/scans" className="text-sm text-sx-muted hover:text-sx-text">← Scans</Link>
      </div>
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{data.domain_name}</h1>
        <span className="text-sx-muted">{data.engine_name}</span>
        <span className={'rounded px-2 py-0.5 text-xs ' + st.cls}>{st.label}</span>
      </div>

      {data.scan_status === 1 && (
        <div className="mb-6">
          <div className="mb-1 flex justify-between text-xs text-sx-muted"><span>Progress</span><span>{data.progress}%</span></div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-sx-surface-2">
            <div className="h-full bg-sx-primary" style={{ width: `${data.progress}%` }} />
          </div>
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Subdomains" value={data.subdomain_count} />
        <Stat label="Endpoints" value={data.endpoint_count} />
        <Stat label="Vulnerabilities" value={data.vulnerability_count} />
        <Stat label="OSINT" value={data.osint_count} />
      </div>

      <div className="mb-2 grid grid-cols-2 gap-4 text-sm text-sx-muted md:grid-cols-2">
        <div>Started: <span className="text-sx-text">{fmt(data.start_scan_date)}</span></div>
        <div>Stopped: <span className="text-sx-text">{fmt(data.stop_scan_date)}</span></div>
      </div>

      <h2 className="mb-3 mt-6 text-base font-medium">Activity timeline</h2>
      <div className="rounded-xl border border-sx-border bg-sx-surface">
        {data.activities.length === 0 && <p className="px-4 py-3 text-sx-muted">No activities yet.</p>}
        {data.activities.map((a) => {
          const ast = STATUS[a.status] ?? STATUS[-1]
          return (
            <div key={a.id} className="flex items-center gap-3 border-b border-sx-border px-4 py-2 last:border-0">
              <span className={'rounded px-2 py-0.5 text-xs ' + ast.cls}>{ast.label}</span>
              <span className="flex-1">{a.title || a.name}</span>
              <span className="text-xs text-sx-muted">{fmt(a.time)}</span>
              {a.error_message && <span className="text-xs text-sx-critical" title={a.error_message}>⚠</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}
