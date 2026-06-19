import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef, type CellContext } from '@tanstack/react-table'
import { Network, Server, ShieldCheck } from 'lucide-react'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/ui/Badge'

type Port = { number: number; service_name: string | null; is_uncommon: boolean }
type Ip = { address: string; is_cdn: boolean; ports: Port[] }

function PortsCell({ row }: CellContext<Ip, unknown>) {
  const ports = row.original.ports
  if (!ports.length) return <span className="text-sx-muted">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {ports.map((p) => (
        <Badge key={p.number} className={p.is_uncommon ? 'text-sx-medium' : 'text-sx-muted'}>
          <span className="sx-num">{p.number}</span>{p.service_name ? <span className="opacity-70">/{p.service_name}</span> : null}
        </Badge>
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
    { accessorKey: 'address', header: 'IP', cell: (c) => (
        <span className="inline-flex items-center gap-1.5 font-medium text-sx-text">
          <Server size={13} className="text-sx-muted" />
          <span className="sx-num">{c.getValue<string>()}</span>
        </span>
      ) },
    { accessorKey: 'is_cdn', header: 'CDN', cell: (c) => c.getValue<boolean>()
        ? <Badge className="text-sx-info"><ShieldCheck size={12} /> CDN</Badge>
        : <span className="text-sx-muted">—</span> },
    { id: 'ports', header: 'Open ports', cell: PortsCell },
  ], [])
  return (
    <DataTable
      data={data ?? []}
      columns={columns}
      countLabel="IPs"
      loading={isLoading}
      error={isError}
      initialSort={[{ id: 'address', desc: false }]}
      emptyIcon={<Network size={22} />}
      emptyLabel="No IPs for this scan."
    />
  )
}
