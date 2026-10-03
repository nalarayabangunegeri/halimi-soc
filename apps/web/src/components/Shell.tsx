import Link from 'next/link'
import { ConnectionIndicator } from './RealtimeProvider'
import { SignOutButton } from './SignOutButton'

// The application chrome.
//
// The nav shows counts so an operator can see whether anything needs attention
// without opening a page. A count that fails to load is omitted rather than shown
// as zero: displaying "0 alerts" when the count is unknown would be a lie an
// operator might act on.

export interface NavCounts {
  alerts?: number
  incidents?: number
  agents?: number
}

interface ShellProps {
  title: string
  subtitle?: string
  username: string
  role: string
  counts?: NavCounts
  headerExtras?: React.ReactNode
  children: React.ReactNode
  active: string
}

const NAV = [
  { href: '/', label: 'Overview', key: 'overview', count: undefined },
  { href: '/alerts', label: 'Alerts', key: 'alerts', count: 'alerts' as const },
  { href: '/incidents', label: 'Incidents', key: 'incidents', count: 'incidents' as const },
  { href: '/events', label: 'Events', key: 'events', count: undefined },
  { href: '/assets', label: 'Assets', key: 'assets', count: undefined },
  { href: '/agents', label: 'Agents', key: 'agents', count: 'agents' as const },
  { href: '/rules', label: 'Rules', key: 'rules', count: undefined },
  { href: '/audit', label: 'Audit', key: 'audit', count: undefined },
]

export function Shell({ title, subtitle, username, role, counts, headerExtras, children, active }: ShellProps) {
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          HalimiSOC
          <small>Security ops</small>
        </div>
        {NAV.map((item) => {
          const count = item.count && counts ? counts[item.count] : undefined
          return (
            <Link
              key={item.key}
              href={item.href}
              className="nav-link"
              aria-current={active === item.key ? 'page' : undefined}
            >
              <span>{item.label}</span>
              {count !== undefined ? <span className="nav-count">{count}</span> : null}
            </Link>
          )
        })}
      </nav>

      <div className="main">
        <header className="topbar">
          <div>
            <h1 className="page-title">{title}</h1>
            {subtitle ? <p className="page-subtitle">{subtitle}</p> : null}
          </div>
          {headerExtras}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <ConnectionIndicator />
            <span className="dim nowrap" style={{ fontSize: 12 }}>
              {username} · {role}
            </span>
            <SignOutButton />
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  )
}
