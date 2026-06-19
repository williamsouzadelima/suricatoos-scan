import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Radar, Play, Square, Network, ShieldAlert, ChevronRight, Clock } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { useToast } from '../components/ui/Toast'
import { Select } from '../components/ui/Select'
import { Tip } from '../components/ui/Tooltip'
import { PageHeader } from '../components/ui/PageHeader'
import { Card, SectionHeader } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { EmptyState } from '../components/ui/EmptyState'
import { Skeleton } from '../components/ui/Skeleton'

type Scan = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; stop_scan_date: string | null
  subdomain_count: number; vulnerability_count: number
}
type Options = { targets: { id: number; name: string }[]; engines: { id: number; name: string }[] }

const STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'text-sx-info' },
  0: { label: 'Failed', cls: 'text-sx-critical' },
  1: { label: 'Running', cls: 'text-sx-medium' },
  2: { label: 'Success', cls: 'text-sx-success' },
  3: { label: 'Aborted', cls: 'text-sx-muted' },
}

function fmt(d: string | null) { return d ? new Date(d).toLocaleString() : '—' }

export function Scans() {
  const qc = useQueryClient()
  const { currentSlug } = useProject()
  const toast = useToast()
  const [domainId, setDomainId] = useState('')
  const [engineId, setEngineId] = useState('')

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
    onSuccess: () => { toast({ title: 'Scan started', variant: 'success' }); setDomainId(''); setEngineId(''); qc.invalidateQueries({ queryKey: ['scans'] }) },
    onError: (e: any) => toast({ title: 'Failed to start scan', description: e?.response?.data?.error, variant: 'error' }),
  })
  const stop = useMutation({
    mutationFn: async (id: number) => (await api.post('/action/stop/scan/', { scan_ids: [id] })).data,
    onSuccess: () => { toast({ title: 'Scan stopped' }); qc.invalidateQueries({ queryKey: ['scans'] }) },
    onError: () => toast({ title: 'Failed to stop scan', variant: 'error' }),
  })

  const rows = scans.data ?? []

  return (
    <div>
      <PageHeader icon={<Radar size={20} />} title="Scans" subtitle="Launch scans and track their status." />

      {/* Launch form */}
      <Card accent className="mb-6">
        <SectionHeader title="Start a scan" icon={<Radar size={14} />} />
        <div className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
          <Select value={domainId} onValueChange={setDomainId} placeholder="Target…" className="w-full sm:w-64"
            options={(options.data?.targets ?? []).map((t) => ({ value: String(t.id), label: t.name }))} />
          <Select value={engineId} onValueChange={setEngineId} placeholder="Engine…" className="w-full sm:w-64"
            options={(options.data?.engines ?? []).map((en) => ({ value: String(en.id), label: en.name }))} />
          <button
            disabled={!currentSlug || !domainId || !engineId || start.isPending}
            onClick={() => start.mutate()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-sx-primary px-4 py-1.5 text-sm font-semibold text-white transition-colors hover:bg-sx-primary-600 disabled:cursor-not-allowed disabled:opacity-50 sm:ml-auto"
          >
            <Play size={14} />
            {start.isPending ? 'Starting…' : 'Start scan'}
          </button>
        </div>
      </Card>

      {/* Scan list */}
      <Card accent>
        <SectionHeader
          title="Scans"
          icon={<Radar size={14} />}
          action={<span className="sx-num text-xs text-sx-muted">{scans.isLoading ? '—' : `${rows.length} total`}</span>}
        />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-sx-border text-left">
              <tr className="sx-uplabel text-[11px] text-sx-muted">
                <th className="px-4 py-2.5 font-semibold">Target</th>
                <th className="px-4 py-2.5 font-semibold">Engine</th>
                <th className="px-4 py-2.5 font-semibold">Status</th>
                <th className="px-4 py-2.5 font-semibold">Started</th>
                <th className="px-4 py-2.5 font-semibold text-right">Subdomains</th>
                <th className="px-4 py-2.5 font-semibold text-right">Vulns</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-sx-border">
              {scans.isLoading ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 7 }).map((__, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                    ))}
                  </tr>
                ))
              ) : scans.isError ? (
                <tr>
                  <td colSpan={7}>
                    <EmptyState icon={<ShieldAlert size={22} />} title="Failed to load scans." />
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <EmptyState icon={<Radar size={22} />} title="No scans yet." hint="Pick a target and engine above to launch your first scan." />
                  </td>
                </tr>
              ) : (
                rows.map((s) => {
                  const st = STATUS[s.scan_status] ?? STATUS[-1]
                  return (
                    <tr key={s.id} className="group transition-colors hover:bg-sx-surface-2/60">
                      <td className="px-4 py-2.5">
                        <Link to={`/scans/${s.id}`} className="inline-flex items-center gap-1.5 font-medium text-sx-primary hover:underline">
                          {s.domain_name}
                          <ChevronRight size={13} className="opacity-0 transition-opacity group-hover:opacity-100" />
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 text-sx-muted">{s.engine_name}</td>
                      <td className="px-4 py-2.5">
                        <Badge className={st.cls}>
                          <span className={'h-1.5 w-1.5 rounded-full bg-current ' + (s.scan_status === 1 ? 'animate-pulse' : '')} />
                          {st.label}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1.5 text-sx-muted">
                          <Clock size={13} className="opacity-70" />
                          {fmt(s.start_scan_date)}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <span className="inline-flex items-center justify-end gap-1.5 sx-num">
                          <Network size={13} className="text-sx-muted" />
                          {s.subdomain_count}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <span className={'sx-num ' + (s.vulnerability_count > 0 ? 'text-sx-text' : 'text-sx-muted')}>
                          {s.vulnerability_count}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {s.scan_status === 1 && (
                          <Tip content="Stop this running scan">
                            <button onClick={() => stop.mutate(s.id)} disabled={stop.isPending}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-sx-critical/60 px-2.5 py-1 text-xs font-medium text-sx-critical transition-colors hover:bg-sx-critical/10 disabled:opacity-50">
                              <Square size={12} />
                              Stop
                            </button>
                          </Tip>
                        )}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
