import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'

type Scan = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; stop_scan_date: string | null
  subdomain_count: number; vulnerability_count: number
}
type Options = { targets: { id: number; name: string }[]; engines: { id: number; name: string }[] }

const STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'bg-sx-info/20 text-sx-info' },
  0: { label: 'Failed', cls: 'bg-sx-critical/20 text-sx-critical' },
  1: { label: 'Running', cls: 'bg-sx-medium/20 text-sx-medium' },
  2: { label: 'Success', cls: 'bg-sx-success/20 text-sx-success' },
  3: { label: 'Aborted', cls: 'bg-sx-surface-2 text-sx-muted' },
}

function fmt(d: string | null) { return d ? new Date(d).toLocaleString() : '—' }

export function Scans() {
  const qc = useQueryClient()
  const { currentSlug } = useProject()
  const [domainId, setDomainId] = useState('')
  const [engineId, setEngineId] = useState('')
  const [msg, setMsg] = useState('')

  const scans = useQuery({
    queryKey: ['scans', currentSlug],
    queryFn: async () => (await api.get<Scan[]>('/scans/', { params: { project: currentSlug } })).data,
    refetchInterval: 5000, // keep running scans fresh
  })
  const options = useQuery({
    queryKey: ['scan-options', currentSlug],
    queryFn: async () => (await api.get<Options>('/scan-options/', { params: { project: currentSlug } })).data,
  })

  const start = useMutation({
    mutationFn: async () => (await api.post('/start-scan/', { domain_id: domainId, engine_id: engineId })).data,
    onSuccess: () => { setMsg('Scan started.'); qc.invalidateQueries({ queryKey: ['scans'] }) },
    onError: (e: any) => setMsg(e?.response?.data?.error || 'Failed to start scan'),
  })
  const stop = useMutation({
    mutationFn: async (id: number) => (await api.post('/action/stop/scan/', { scan_ids: [id] })).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Scans</h1>

      <div className="mb-6 rounded-xl border border-sx-border bg-sx-surface p-4">
        <div className="mb-2 text-sm font-medium">Start a scan</div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={domainId} onChange={(e) => setDomainId(e.target.value)}
            className="rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm">
            <option value="">Target…</option>
            {options.data?.targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <select value={engineId} onChange={(e) => setEngineId(e.target.value)}
            className="rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm">
            <option value="">Engine…</option>
            {options.data?.engines.map((en) => <option key={en.id} value={en.id}>{en.name}</option>)}
          </select>
          <button disabled={!domainId || !engineId || start.isPending}
            onClick={() => { setMsg(''); start.mutate() }}
            className="rounded-lg bg-sx-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-sx-primary-600 disabled:opacity-50">
            {start.isPending ? 'Starting…' : 'Start scan'}
          </button>
          {msg && <span className="text-sm text-sx-muted">{msg}</span>}
        </div>
      </div>

      {scans.isLoading && <p className="text-sx-muted">Loading…</p>}
      {scans.isError && <p className="text-sx-critical">Failed to load scans.</p>}
      {scans.data && (
        <div className="overflow-x-auto rounded-xl border border-sx-border">
          <table className="w-full text-sm">
            <thead className="bg-sx-surface-2 text-left text-sx-muted">
              <tr>
                <th className="px-4 py-2">Target</th><th className="px-4 py-2">Engine</th>
                <th className="px-4 py-2">Status</th><th className="px-4 py-2">Started</th>
                <th className="px-4 py-2">Subdomains</th><th className="px-4 py-2">Vulns</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => {
                const st = STATUS[s.scan_status] ?? STATUS[-1]
                return (
                  <tr key={s.id} className="border-t border-sx-border">
                    <td className="px-4 py-2">{s.domain_name}</td>
                    <td className="px-4 py-2 text-sx-muted">{s.engine_name}</td>
                    <td className="px-4 py-2"><span className={'rounded px-2 py-0.5 text-xs ' + st.cls}>{st.label}</span></td>
                    <td className="px-4 py-2 text-sx-muted">{fmt(s.start_scan_date)}</td>
                    <td className="px-4 py-2">{s.subdomain_count}</td>
                    <td className="px-4 py-2">{s.vulnerability_count}</td>
                    <td className="px-4 py-2 text-right">
                      {s.scan_status === 1 && (
                        <button onClick={() => stop.mutate(s.id)} disabled={stop.isPending}
                          className="rounded border border-sx-critical px-2 py-1 text-xs text-sx-critical hover:bg-sx-critical/10 disabled:opacity-50">Stop</button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {scans.data.length === 0 && <p className="px-4 py-3 text-sx-muted">No scans yet.</p>}
        </div>
      )}
    </div>
  )
}
