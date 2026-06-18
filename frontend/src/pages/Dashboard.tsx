import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useAuth } from '../auth/auth'

type OsintResult = {
  id: number; bucket: string; event_type: string; data: string; is_malicious: boolean
}

const BUCKET_LABEL: Record<string, string> = {
  malicious: 'Malicious / Blacklisted', code_repos: 'Public Code Repos',
  infra_dns: 'DNS & Email', netblock_asn: 'Netblock / ASN', affiliates: 'Affiliates',
  cohosted: 'Co-Hosted', geo: 'Geolocation', web_tech: 'Web Tech',
}

export function Dashboard() {
  const { logout } = useAuth()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['osint', 12],
    queryFn: async () => (await api.get<OsintResult[]>('/listOsintResults/', { params: { scan_history: 12 } })).data,
  })

  return (
    <div className="min-h-screen bg-sx-bg text-sx-text">
      <header className="flex items-center justify-between border-b border-sx-border px-6 py-4">
        <h1 className="text-lg font-semibold">Suricatoos <span className="text-sx-muted text-sm">SPA</span></h1>
        <button onClick={logout} className="rounded-lg border border-sx-border px-3 py-1.5 text-sm hover:border-sx-primary">Logout</button>
      </header>
      <main className="p-6">
        <h2 className="mb-4 text-base font-medium">OSINT Intelligence <span className="text-sx-muted text-sm">(demo: scan 12)</span></h2>
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
      </main>
    </div>
  )
}
