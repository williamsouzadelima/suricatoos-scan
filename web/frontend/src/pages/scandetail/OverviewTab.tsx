import { Network, Globe, ShieldAlert, Eye, Activity as ActivityIcon, AlertTriangle, Clock } from 'lucide-react'
import { Card, SectionHeader } from '../../components/ui/Card'
import { StatCard } from '../../components/ui/StatCard'
import { Badge } from '../../components/ui/Badge'
import { EmptyState } from '../../components/ui/EmptyState'
import { type ScanDetail, STATUS, fmt } from './types'

export function OverviewTab({ data }: { data: ScanDetail }) {
  return (
    <div>
      {data.scan_status === 1 && (
        <Card accent className="mb-6 p-4">
          <div className="mb-1.5 flex justify-between text-xs">
            <span className="sx-uplabel font-semibold text-sx-muted">Scan progress</span>
            <span className="sx-num font-semibold text-sx-primary">{data.progress ?? 0}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-sx-surface-2">
            <div className="h-full rounded-full bg-sx-primary transition-all duration-500" style={{ width: `${data.progress ?? 0}%` }} />
          </div>
        </Card>
      )}

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard icon={<Network size={20} />} label="Subdomains" value={data.subdomain_count} accentText="text-sx-info" />
        <StatCard icon={<Globe size={20} />} label="Endpoints" value={data.endpoint_count} accentText="text-sx-info" />
        <StatCard icon={<ShieldAlert size={20} />} label="Vulnerabilities" value={data.vulnerability_count} accentText="text-sx-primary" />
        <StatCard icon={<Eye size={20} />} label="OSINT" value={data.osint_count} accentText="text-sx-info" />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Card className="flex items-center gap-3 p-4">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-sx-border bg-sx-surface-2 text-sx-success"><Clock size={16} /></span>
          <div className="min-w-0">
            <div className="sx-uplabel text-[11px] font-semibold text-sx-muted">Started</div>
            <div className="truncate text-sm text-sx-text">{fmt(data.start_scan_date)}</div>
          </div>
        </Card>
        <Card className="flex items-center gap-3 p-4">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-sx-border bg-sx-surface-2 text-sx-muted"><Clock size={16} /></span>
          <div className="min-w-0">
            <div className="sx-uplabel text-[11px] font-semibold text-sx-muted">Stopped</div>
            <div className="truncate text-sm text-sx-text">{fmt(data.stop_scan_date)}</div>
          </div>
        </Card>
      </div>

      <Card accent>
        <SectionHeader title="Activity timeline" icon={<ActivityIcon size={14} />} />
        {data.activities.length === 0 ? (
          <EmptyState icon={<ActivityIcon size={22} />} title="No activities yet." />
        ) : (
          <ul className="divide-y divide-sx-border">
            {data.activities.map((a) => {
              const ast = STATUS[a.status] ?? STATUS[-1]
              return (
                <li key={a.id} className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-sx-surface-2/60">
                  <Badge className={ast.cls}>{ast.label}</Badge>
                  <span className="min-w-0 flex-1 truncate text-sm text-sx-text">{a.title || a.name}</span>
                  {a.error_message && (
                    <span title={a.error_message} className="shrink-0 text-sx-critical">
                      <AlertTriangle size={14} aria-label="Error" />
                    </span>
                  )}
                  <span className="shrink-0 text-xs text-sx-muted">{fmt(a.time)}</span>
                </li>
              )
            })}
          </ul>
        )}
      </Card>
    </div>
  )
}
