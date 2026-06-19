import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { FolderTree } from 'lucide-react'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/ui/Badge'
import { statusCls } from './types'

type Dir = { subdomain_name: string; name: string; http_status: number; length: number; words: number; lines: number }

export function DirectoriesTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-directories', scanId],
    queryFn: async () => (await api.get<Dir[]>('/scan-directories/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Dir>[]>(() => [
    { accessorKey: 'subdomain_name', header: 'Subdomain', cell: (c) => <span className="text-sx-muted">{c.getValue<string>()}</span> },
    { accessorKey: 'name', header: 'Path', cell: (c) => <span className="font-medium text-sx-text">{c.getValue<string>()}</span> },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>()
        return s
          ? <Badge className={statusCls(s)}><span className="sx-num">{s}</span></Badge>
          : <span className="text-sx-muted">—</span>
      } },
    { accessorKey: 'length', header: 'Length', cell: (c) => <span className="sx-num text-sx-muted">{c.getValue<number>()}</span> },
    { accessorKey: 'words', header: 'Words', cell: (c) => <span className="sx-num text-sx-muted">{c.getValue<number>()}</span> },
    { accessorKey: 'lines', header: 'Lines', cell: (c) => <span className="sx-num text-sx-muted">{c.getValue<number>()}</span> },
  ], [])
  return (
    <DataTable
      data={data ?? []}
      columns={columns}
      countLabel="paths"
      loading={isLoading}
      error={isError}
      initialSort={[{ id: 'subdomain_name', desc: false }]}
      emptyIcon={<FolderTree size={22} />}
      emptyLabel="No directory results for this scan."
    />
  )
}
