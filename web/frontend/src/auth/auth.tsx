import { createContext, useContext, useState, ReactNode } from 'react'
import { api, tokenStore } from '../api/client'

type AuthCtx = {
  isAuthenticated: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}
const Ctx = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setAuth] = useState<boolean>(!!tokenStore.access)
  async function login(username: string, password: string) {
    const res = await api.post('/token/', { username, password })
    tokenStore.set({ access: res.data.access, refresh: res.data.refresh })
    setAuth(true)
  }
  function logout() {
    // Best-effort: revoke the refresh token server-side (blacklist) so it can't
    // be reused after logout; clear local state regardless of the call's outcome.
    const refresh = tokenStore.refresh
    if (refresh) api.post('/token/logout/', { refresh }).catch(() => {})
    tokenStore.clear(); setAuth(false)
  }
  return <Ctx.Provider value={{ isAuthenticated, login, logout }}>{children}</Ctx.Provider>
}

export function useAuth() {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth must be used within AuthProvider')
  return c
}
