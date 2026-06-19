import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef, type CellContext } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'

type Port = { number: number; service_name: string | null; is_uncommon: boolean }
type Ip = { address: string; is_cdn: boolean; ports: Port[] }

function PortsCell({ row }: CellContext<Ip, unknown>) {
  const ports = row.original.ports
  if (!ports.length) return <span className="text-sx-muted">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {ports.map((p) => (
        <span
          key={p.number}
          className={'rounded px-1.5 py-0.5 text-xs ' + (p.is_uncommon ? 'bg-sx-medium/20 text-sx-medium' : 'bg-sx-surface-2 text-sx-muted')}
        >
          {p.number}{p.service_name ? ('/' + p.service_name) : ''}
        </span>
      ))}
    </div>
  )
}

export function IpsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-ips', scanId],
    queryFn: async () => (await api.get<Ip[]>('/ips/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Ip>[]>(() => [
    { accessorKey: 'address', header: 'IP' },
    { accessorKey: 'is_cdn', header: 'CDN', cell: (c) => c.getValue<boolean>() ? 'yes' : '—' },
    { id: 'ports', header: 'Open ports', cell: PortsCell },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load IPs.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No IPs for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="IPs" initialSort={[{ id: 'address', desc: false }]} />
}
