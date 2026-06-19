import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'

type Tech = { name: string; subdomain_count: number }

export function TechTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-tech', scanId],
    queryFn: async () => (await api.get<Tech[]>('/technologies/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Tech>[]>(() => [
    { accessorKey: 'name', header: 'Technology' },
    { accessorKey: 'subdomain_count', header: 'Subdomains' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load technologies.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No technologies for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="technologies" initialSort={[{ id: 'subdomain_count', desc: true }]} />
}
