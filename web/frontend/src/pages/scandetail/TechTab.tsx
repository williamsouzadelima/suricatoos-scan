import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Cpu } from 'lucide-react'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/ui/Badge'

type Tech = { name: string; subdomain_count: number }

export function TechTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-tech', scanId],
    queryFn: async () => (await api.get<Tech[]>('/technologies/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Tech>[]>(() => [
    { accessorKey: 'name', header: 'Technology', cell: (c) => (
        <span className="inline-flex items-center gap-1.5 font-medium text-sx-text">
          <Cpu size={13} className="text-sx-muted" />
          {c.getValue<string>()}
        </span>
      ) },
    { accessorKey: 'subdomain_count', header: 'Subdomains', cell: (c) => (
        <Badge className="text-sx-info"><span className="sx-num">{c.getValue<number>()}</span></Badge>
      ) },
  ], [])
  return (
    <DataTable
      data={data ?? []}
      columns={columns}
      countLabel="technologies"
      loading={isLoading}
      error={isError}
      initialSort={[{ id: 'subdomain_count', desc: true }]}
      emptyIcon={<Cpu size={22} />}
      emptyLabel="No technologies for this scan."
    />
  )
}
