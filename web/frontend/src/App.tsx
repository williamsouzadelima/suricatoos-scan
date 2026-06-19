import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './auth/auth'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AppLayout } from './components/AppLayout'
import { ProjectProvider } from './project/project'

// Route-level code splitting: each page ships as its own chunk so the initial
// load only pulls the shell + the first route. Pages use named exports, hence
// the .then(default) adapters.
const Login = lazy(() => import('./pages/Login').then((m) => ({ default: m.Login })))
const Dashboard = lazy(() => import('./pages/Dashboard').then((m) => ({ default: m.Dashboard })))
const Osint = lazy(() => import('./pages/Osint').then((m) => ({ default: m.Osint })))
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities').then((m) => ({ default: m.Vulnerabilities })))
const Scans = lazy(() => import('./pages/Scans').then((m) => ({ default: m.Scans })))
const Subdomains = lazy(() => import('./pages/Subdomains').then((m) => ({ default: m.Subdomains })))
const Endpoints = lazy(() => import('./pages/Endpoints').then((m) => ({ default: m.Endpoints })))
const LeakedSecrets = lazy(() => import('./pages/LeakedSecrets').then((m) => ({ default: m.LeakedSecrets })))
const ScanDetail = lazy(() => import('./pages/ScanDetail').then((m) => ({ default: m.ScanDetail })))
const Targets = lazy(() => import('./pages/Targets').then((m) => ({ default: m.Targets })))

function FullScreenFallback() {
  return (
    <div className="grid min-h-screen place-items-center bg-sx-bg">
      <div className="h-7 w-7 animate-spin rounded-full border-2 border-sx-border border-t-sx-primary" />
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter basename={import.meta.env.PROD ? "/app" : "/"}>
        <Suspense fallback={<FullScreenFallback />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<ProtectedRoute><ProjectProvider><AppLayout /></ProjectProvider></ProtectedRoute>}>
              <Route index element={<Dashboard />} />
              <Route path="targets" element={<Targets />} />
              <Route path="scans" element={<Scans />} />
              <Route path="scans/:id" element={<ScanDetail />} />
              <Route path="subdomains" element={<Subdomains />} />
              <Route path="endpoints" element={<Endpoints />} />
              <Route path="vulnerabilities" element={<Vulnerabilities />} />
              <Route path="secrets" element={<LeakedSecrets />} />
              <Route path="osint" element={<Osint />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  )
}
