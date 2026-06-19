import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { AuthImage } from '../../components/AuthImage'

type Shot = { subdomain_id: number; subdomain_name: string; image_url: string }

export function ScreenshotsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-screenshots', scanId],
    queryFn: async () => (await api.get<Shot[]>('/screenshots/', { params: { scan_history: scanId } })).data,
  })
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load screenshots.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No screenshots for this scan.</p>
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {data.map((s) => (
        <div key={s.subdomain_id} className="overflow-hidden rounded-xl border border-sx-border bg-sx-surface">
          <AuthImage src={s.image_url} alt={s.subdomain_name} className="h-48 w-full object-cover object-top" />
          <div className="truncate px-3 py-2 text-sm" title={s.subdomain_name}>{s.subdomain_name}</div>
        </div>
      ))}
    </div>
  )
}
