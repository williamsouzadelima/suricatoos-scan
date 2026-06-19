import type { ComponentType } from 'react'
import { LayoutDashboard, Target, Radar, Network, Globe, ShieldAlert, KeyRound, Eye } from 'lucide-react'

// Single source of truth for primary navigation — consumed by the sidebar and
// the ⌘K command palette so they never drift apart.
export type IconType = ComponentType<{ size?: number | string; className?: string }>
export type NavItem = { to: string; label: string; end?: boolean; icon: IconType }

export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', end: true, icon: LayoutDashboard },
  { to: '/targets', label: 'Targets', icon: Target },
  { to: '/scans', label: 'Scans', icon: Radar },
  { to: '/subdomains', label: 'Subdomains', icon: Network },
  { to: '/endpoints', label: 'Endpoints', icon: Globe },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { to: '/secrets', label: 'Secrets', icon: KeyRound },
  { to: '/osint', label: 'OSINT', icon: Eye },
]
