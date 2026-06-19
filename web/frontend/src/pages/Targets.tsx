import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Target as TargetIcon, Plus, CalendarPlus, Radar, Globe } from 'lucide-react'
import { api } from '../api/client'
import { useProject } from '../project/project'
import { useToast } from '../components/ui/Toast'
import { PageHeader } from '../components/ui/PageHeader'
import { Card, SectionHeader } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { DataTable } from '../components/DataTable'

type Target = { id: number; name: string; insert_date: string | null; start_scan_date: string | null }
function fmt(d: string | null) { return d ? new Date(d).toLocaleDateString() : '—' }

export function Targets() {
  const { currentSlug } = useProject()
  const qc = useQueryClient()
  const toast = useToast()
  const [domain, setDomain] = useState('')

  const targets = useQuery({
    queryKey: ['targets', currentSlug],
    queryFn: async () => (await api.get<Target[]>('/targets/', { params: { project: currentSlug } })).data,
  })

  const add = useMutation({
    mutationFn: async () => (await api.post('/add/target/', { domain_name: domain, slug: currentSlug })).data,
    onSuccess: (d: any) => {
      if (d?.status === false) { toast({ title: 'Could not add target', description: d.message, variant: 'error' }); return }
      toast({ title: 'Target added', description: domain, variant: 'success' })
      setDomain(''); qc.invalidateQueries({ queryKey: ['targets'] })
    },
    onError: () => toast({ title: 'Could not add target', variant: 'error' }),
  })

  const columns = useMemo<ColumnDef<Target>[]>(() => [
    {
      accessorKey: 'name', header: 'Target', cell: (c) => (
        <span className="flex items-center gap-2 font-medium text-sx-text">
          <Globe size={14} className="shrink-0 text-sx-muted" />
          <span className="break-all">{c.getValue<string>()}</span>
        </span>
      ),
    },
    {
      accessorKey: 'insert_date', header: 'Added', cell: (c) => (
        <span className="inline-flex items-center gap-1.5 text-sx-muted">
          <CalendarPlus size={13} className="shrink-0 opacity-70" />
          {fmt(c.getValue<string | null>())}
        </span>
      ),
    },
    {
      accessorKey: 'start_scan_date', header: 'Last scanned', cell: (c) => {
        const d = c.getValue<string | null>()
        return d
          ? (
            <Badge className="text-sx-success">
              <Radar size={12} />
              {fmt(d)}
            </Badge>
          )
          : <span className="text-sx-muted">Never scanned</span>
      },
    },
  ], [])

  const canSubmit = !!domain.trim() && !!currentSlug && !add.isPending

  return (
    <div>
      <PageHeader
        icon={<TargetIcon size={20} />}
        title="Targets"
        subtitle="Add and manage reconnaissance targets."
      />

      <Card accent className="mb-6">
        <SectionHeader title="Add target" icon={<Plus size={14} />} />
        <form
          className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center"
          onSubmit={(e) => { e.preventDefault(); if (canSubmit) add.mutate() }}
        >
          <div className="relative flex-1">
            <Globe size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sx-muted" />
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full rounded-lg border border-sx-border bg-sx-surface-2 py-2 pl-9 pr-3 text-sm outline-none transition-colors focus:border-sx-primary"
            />
          </div>
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-sx-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-sx-primary-600 disabled:opacity-50"
          >
            <Plus size={15} />
            {add.isPending ? 'Adding…' : 'Add target'}
          </button>
        </form>
      </Card>

      <DataTable
        data={targets.data ?? []}
        columns={columns}
        countLabel="targets"
        loading={targets.isLoading}
        error={targets.isError}
        initialSort={[{ id: 'name', desc: false }]}
        searchPlaceholder="Search targets…"
        emptyIcon={<TargetIcon size={22} />}
        emptyLabel="No targets in this project yet."
      />
    </div>
  )
}
