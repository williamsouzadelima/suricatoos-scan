import axios from 'axios'

// Same-origin '/api' (Vite proxies to Django in dev; same host in prod).
export const api = axios.create({ baseURL: '/api' })

export const tokenStore = {
  get access() { return localStorage.getItem('sx_access') },
  get refresh() { return localStorage.getItem('sx_refresh') },
  set({ access, refresh }: { access: string; refresh?: string }) {
    localStorage.setItem('sx_access', access)
    if (refresh) localStorage.setItem('sx_refresh', refresh)
  },
  clear() { localStorage.removeItem('sx_access'); localStorage.removeItem('sx_refresh') },
}

api.interceptors.request.use((config) => {
  const t = tokenStore.access
  if (t) config.headers.Authorization = `Bearer ${t}`
  return config
})

// On 401, try one refresh; if it fails, clear tokens and bounce to login.
let refreshing: Promise<string | null> | null = null
api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retried && tokenStore.refresh) {
      original._retried = true
      refreshing = refreshing ?? axios
        .post('/api/token/refresh/', { refresh: tokenStore.refresh })
        .then((res) => { tokenStore.set({ access: res.data.access }); return res.data.access })
        .catch(() => { tokenStore.clear(); return null })
        .finally(() => { refreshing = null })
      const newAccess = await refreshing
      if (newAccess) { original.headers.Authorization = `Bearer ${newAccess}`; return api(original) }
      // In prod the SPA is mounted at /app (BrowserRouter basename); send the
      // user to the SPA login, not the legacy Django template login at /login.
      const loginPath = import.meta.env.PROD ? '/app/login' : '/login'
      if (location.pathname !== loginPath) location.href = loginPath
    }
    return Promise.reject(error)
  },
)
