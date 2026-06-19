import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { useToast } from '../components/ui/Toast'
import { Modal } from '../components/ui/Dialog'

type Target = { id: number; name: string; insert_date: string | null; start_scan_date: string | null }
function fmt(d: string | null) { return d ? new Date(d).toLocaleDateString() : '—' }

export function Targets() {
  const { currentSlug } = useProject()
  const qc = useQueryClient()
  const toast = useToast()
  const [domain, setDomain] = useState('')
  const [open, setOpen] = useState(false)

  const targets = useQuery({
    queryKey: ['targets', currentSlug],
    queryFn: async () => (await api.get<Target[]>('/targets/', { params: { project: currentSlug } })).data,
  })

  const add = useMutation({
    mutationFn: async () => (await api.post('/add/target/', { domain_name: domain, slug: currentSlug })).data,
    onSuccess: (d: any) => {
      if (d?.status === false) { toast({ title: 'Could not add target', description: d.message, variant: 'error' }); return }
      toast({ title: 'Target added', description: domain, variant: 'success' })
      setDomain(''); setOpen(false); qc.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: () => toast({ title: 'Could not add target', variant: 'error' }),
  })

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h1 className="sx-uplabel text-xl font-semibold">Targets</h1>
        <button onClick={() => setOpen(true)} disabled={!currentSlug}
          className="rounded-lg bg-sx-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-sx-primary-600 disabled:opacity-50">
          + Add target
        </button>
      </div>

      <Modal open={open} onOpenChange={setOpen} title="Add target" description="Add a domain to this project.">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" autoFocus
          onKeyDown={(e) => { if (e.key === 'Enter' && domain) add.mutate() }}
          className="mb-4 w-full rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-2 text-sm outline-none focus:border-sx-primary" />
        <div className="flex justify-end gap-2">
          <button onClick={() => setOpen(false)} className="rounded-lg border border-sx-border px-4 py-1.5 text-sm text-sx-muted hover:text-sx-text">Cancel</button>
          <button disabled={!domain || add.isPending} onClick={() => add.mutate()}
            className="rounded-lg bg-sx-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-sx-primary-600 disabled:opacity-50">
            {add.isPending ? 'Adding…' : 'Add target'}
          </button>
        </div>
      </Modal>

      {targets.isLoading && <p className="text-sx-muted">Loading…</p>}
      {targets.isError && <p className="text-sx-critical">Failed to load targets.</p>}
      {targets.data && (
        <div className="overflow-x-auto rounded-xl border border-sx-border">
          <table className="w-full text-sm">
            <thead className="bg-sx-surface-2 text-left text-sx-muted">
              <tr><th className="sx-uplabel px-4 py-2 text-[11px]">Target</th><th className="sx-uplabel px-4 py-2 text-[11px]">Added</th><th className="sx-uplabel px-4 py-2 text-[11px]">Last scanned</th></tr>
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
