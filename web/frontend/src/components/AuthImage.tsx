import { useEffect, useState } from 'react'
import { api } from '../api/client'

export function AuthImage({ src, alt, className }: { src: string; alt: string; className?: string }) {
  const [url, setUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let objectUrl: string | null = null
    let active = true
    setFailed(false); setUrl(null)
    api.get(src, { responseType: 'blob' })
      .then((r) => {
        if (!active) return
        objectUrl = URL.createObjectURL(r.data as Blob)
        setUrl(objectUrl)
      })
      .catch(() => active && setFailed(true))
    return () => { active = false; if (objectUrl) URL.revokeObjectURL(objectUrl) }
  }, [src])
  if (failed) return <div className={'flex items-center justify-center bg-sx-surface-2 text-xs text-sx-muted ' + (className ?? '')}>no image</div>
  if (!url) return <div className={'animate-pulse bg-sx-surface-2 ' + (className ?? '')} />
  return <img src={url} alt={alt} className={className} loading="lazy" />
}
