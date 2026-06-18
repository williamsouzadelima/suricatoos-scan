import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useProject } from '../project/project'

type OsintResult = { id: number; bucket: string; event_type: string; data: string; is_malicious: boolean }

const BUCKET_LABEL: Record<string, string> = {
  malicious: 'Malicious / Blacklisted', code_repos: 'Public Code Repos',
  infra_dns: 'DNS & Email', netblock_asn: 'Netblock / ASN', affiliates: 'Affiliates',
  cohosted: 'Co-Hosted', geo: 'Geolocation', web_tech: 'Web Tech',
}

export function Osint() {
  const { currentSlug } = useProject()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['osint', currentSlug],
    queryFn: async () => (await api.get<OsintResult[]>('/listOsintResults/', { params: { project: currentSlug } })).data,
  })
  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold">OSINT Intelligence</h1>
      
      {isLoading && <p className="text-sx-muted">Loading…</p>}
      {isError && <p className="text-sx-critical">Failed to load.</p>}
      {data && (
        <div className="overflow-hidden rounded-xl border border-sx-border">
          <table className="w-full text-sm">
            <thead className="bg-sx-surface-2 text-left text-sx-muted">
              <tr><th className="px-4 py-2">Category</th><th className="px-4 py-2">Type</th><th className="px-4 py-2">Data</th></tr>
            </thead>
            <tbody>
              {data.map((o) => (
                <tr key={o.id} className="border-t border-sx-border">
                  <td className="px-4 py-2">
                    <span className={'rounded px-2 py-0.5 text-xs ' + (o.is_malicious ? 'bg-sx-critical/20 text-sx-critical' : 'bg-sx-surface-2 text-sx-muted')}>
                      {BUCKET_LABEL[o.bucket] ?? o.bucket}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-sx-muted">{o.event_type}</td>
                  <td className="px-4 py-2 break-all">{o.data}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.length === 0 && <p className="px-4 py-3 text-sx-muted">No OSINT results.</p>}
        </div>
      )}
    </div>
  )
}
