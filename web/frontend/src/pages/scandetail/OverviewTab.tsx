import { type ScanDetail, STATUS, fmt } from './types'

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-sx-border bg-sx-surface p-4">
      <div className="text-sm text-sx-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  )
}

export function OverviewTab({ data }: { data: ScanDetail }) {
  return (
    <div>
      {data.scan_status === 1 && (
        <div className="mb-6">
          <div className="mb-1 flex justify-between text-xs text-sx-muted"><span>Progress</span><span>{data.progress ?? 0}%</span></div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-sx-surface-2">
            <div className="h-full bg-sx-primary" style={{ width: `${data.progress ?? 0}%` }} />
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
