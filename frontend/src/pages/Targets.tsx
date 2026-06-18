import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'

type Target = { id: number; name: string; insert_date: string | null; start_scan_date: string | null }
function fmt(d: string | null) { return d ? new Date(d).toLocaleDateString() : '—' }

export function Targets() {
  const { currentSlug } = useProject()
  const qc = useQueryClient()
  const [domain, setDomain] = useState('')
  const [msg, setMsg] = useState('')

  const targets = useQuery({
    queryKey: ['targets', currentSlug],
    queryFn: async () => (await api.get<Target[]>('/targets/', { params: { project: currentSlug } })).data,
  })

  const add = useMutation({
    mutationFn: async () => (await api.post('/add/target/', { domain_name: domain, slug: currentSlug })).data,
    onSuccess: (d: any) => {
      if (d?.status === false) { setMsg(d.message || 'Failed to add target'); return }
      setMsg('Target added.'); setDomain(''); qc.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: () => setMsg('Failed to add target'),
  })

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Targets</h1>

      <div className="mb-6 rounded-xl border border-sx-border bg-sx-surface p-4">
        <div className="mb-2 text-sm font-medium">Add a target</div>
        <div className="flex flex-wrap items-center gap-2">
          <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com"
            onKeyDown={(e) => { if (e.key === 'Enter' && domain) { setMsg(''); add.mutate() } }}
            className="w-72 rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm outline-none focus:border-sx-primary" />
          <button disabled={!domain || !currentSlug || add.isPending} onClick={() => { setMsg(''); add.mutate() }}
            className="rounded-lg bg-sx-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-sx-primary-600 disabled:opacity-50">
            {add.isPending ? 'Adding…' : 'Add target'}
          </button>
          {msg && <span className="text-sm text-sx-muted">{msg}</span>}
        </div>
      </div>

      {targets.isLoading && <p className="text-sx-muted">Loading…</p>}
      {targets.isError && <p className="text-sx-critical">Failed to load targets.</p>}
      {targets.data && (
        <div className="overflow-x-auto rounded-xl border border-sx-border">
          <table className="w-full text-sm">
            <thead className="bg-sx-surface-2 text-left text-sx-muted">
              <tr><th className="px-4 py-2">Target</th><th className="px-4 py-2">Added</th><th className="px-4 py-2">Last scanned</th></tr>
            </thead>
            <tbody>
              {targets.data.map((t) => (
                <tr key={t.id} className="border-t border-sx-border">
                  <td className="px-4 py-2">{t.name}</td>
                  <td className="px-4 py-2 text-sx-muted">{fmt(t.insert_date)}</td>
                  <td className="px-4 py-2 text-sx-muted">{fmt(t.start_scan_date)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {targets.data.length === 0 && <p className="px-4 py-3 text-sx-muted">No targets in this project yet.</p>}
        </div>
      )}
    </div>
  )
}
