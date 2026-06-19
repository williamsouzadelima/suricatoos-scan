export type Activity = { id: number; title: string; name: string; status: number; time: string | null; error_message: string | null }
export type ScanDetail = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; stop_scan_date: string | null
  subdomain_count: number; endpoint_count: number; vulnerability_count: number
  osint_count: number; progress: number; activities: Activity[]
}
export const STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'bg-sx-info/20 text-sx-info' },
  0: { label: 'Failed', cls: 'bg-sx-critical/20 text-sx-critical' },
  1: { label: 'Running', cls: 'bg-sx-medium/20 text-sx-medium' },
  2: { label: 'Success', cls: 'bg-sx-success/20 text-sx-success' },
  3: { label: 'Aborted', cls: 'bg-sx-surface-2 text-sx-muted' },
}
export function fmt(d: string | null) { return d ? new Date(d).toLocaleString() : '—' }
export function statusCls(s: number) {
  if (s >= 200 && s < 300) return 'bg-sx-success/20 text-sx-success'
  if (s >= 300 && s < 400) return 'bg-sx-info/20 text-sx-info'
  if (s >= 400 && s < 500) return 'bg-sx-medium/20 text-sx-medium'
  if (s >= 500) return 'bg-sx-critical/20 text-sx-critical'
  return 'bg-sx-surface-2 text-sx-muted'
}
