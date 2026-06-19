import { useQuery } from '@tanstack/react-query'
import { Image as ImageIcon } from 'lucide-react'
import { api } from '../../api/client'
import { AuthImage } from '../../components/AuthImage'
import { Card } from '../../components/ui/Card'
import { EmptyState } from '../../components/ui/EmptyState'
import { Skeleton } from '../../components/ui/Skeleton'

type Shot = { subdomain_id: number; subdomain_name: string; image_url: string }

export function ScreenshotsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-screenshots', scanId],
    queryFn: async () => (await api.get<Shot[]>('/screenshots/', { params: { scan_history: scanId } })).data,
  })

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-[224px] rounded-xl" />)}
      </div>
    )
  }
  if (isError) {
    return <Card><EmptyState icon={<ImageIcon size={22} />} title="Failed to load screenshots." /></Card>
  }
  if (!data || data.length === 0) {
    return <Card><EmptyState icon={<ImageIcon size={22} />} title="No screenshots for this scan." /></Card>
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {data.map((s) => (
        <Card key={s.subdomain_id} className="group transition-colors duration-200 hover:border-sx-primary/40">
          <AuthImage src={s.image_url} alt={s.subdomain_name} className="h-48 w-full border-b border-sx-border object-cover object-top" />
          <div className="flex items-center gap-1.5 px-3 py-2">
            <ImageIcon size={13} className="shrink-0 text-sx-muted transition-colors group-hover:text-sx-primary" />
            <span className="truncate text-sm text-sx-text" title={s.subdomain_name}>{s.subdomain_name}</span>
          </div>
        </Card>
      ))}
    </div>
  )
}
