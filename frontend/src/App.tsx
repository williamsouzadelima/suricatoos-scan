import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './auth/auth'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AppLayout } from './components/AppLayout'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Osint } from './pages/Osint'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { Scans } from './pages/Scans'
import { Subdomains } from './pages/Subdomains'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter basename={import.meta.env.PROD ? "/app" : "/"}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<Scans />} />
            <Route path="subdomains" element={<Subdomains />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="osint" element={<Osint />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
