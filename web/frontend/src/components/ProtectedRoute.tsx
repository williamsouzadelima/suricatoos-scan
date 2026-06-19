import { Navigate } from 'react-router-dom'
import { ReactNode } from 'react'
import { useAuth } from '../auth/auth'

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth()
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}
