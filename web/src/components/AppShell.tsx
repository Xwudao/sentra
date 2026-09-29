import { Link, Outlet } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { useState } from 'react'

import { useAuth, useTheme } from '@/store/auth'
import { Button, IconButton, cx } from './ui'
import s from './app-shell.module.scss'

interface NavItem {
  to: string
  label: string
  icon: string
}

const groups: { label: string; items: NavItem[] }[] = [
  {
    label: 'Overview',
    items: [{ to: '/', label: 'Dashboard', icon: 'i-lucide-layout-dashboard' }],
  },
  {
    label: 'Traffic',
    items: [{ to: '/traffic/events', label: 'Events', icon: 'i-lucide-activity' }],
  },
  {
    label: 'Security',
    items: [
      { to: '/security/rules', label: 'Rules', icon: 'i-lucide-shield-check' },
      { to: '/security/ip-rules', label: 'IP Rules', icon: 'i-lucide-network' },
      { to: '/security/rate-limit', label: 'Rate Limit', icon: 'i-lucide-gauge' },
      { to: '/security/playground', label: 'Playground', icon: 'i-lucide-flask-conical' },
    ],
  },
  {
    label: 'System',
    items: [{ to: '/settings', label: 'Settings', icon: 'i-lucide-settings' }],
  },
]

export function AppShell({ children }: { children?: ReactNode }) {
  const [open, setOpen] = useState(false)
  const theme = useTheme((t) => t.theme)
  const toggleTheme = useTheme((t) => t.toggle)
  const clear = useAuth((a) => a.clear)

  return (
    <div className={s.shell}>
      {open ? <div className={s.backdrop} onClick={() => setOpen(false)} aria-hidden="true" /> : null}
      <aside className={cx(s.sidebar, open && s.sidebarOpen)}>
        <div className={s.brand}>
          <span className={s.brandMark}>
            <span className="i-lucide-shield-half" />
          </span>
          <span className={s.brandText}>
            <span className={s.brandName}>Sentra</span>
            <span className={s.brandSub}>WAF Console</span>
          </span>
        </div>
        <nav className={s.nav}>
          {groups.map((group) => (
            <div key={group.label} className={s.navGroup}>
              <div className={s.navLabel}>{group.label}</div>
              {group.items.map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  className={s.navItem}
                  activeProps={{ className: cx(s.navItem, s.navActive) }}
                  activeOptions={{ exact: item.to === '/' }}
                  onClick={() => setOpen(false)}
                >
                  <span className={cx(s.navIcon, item.icon)} aria-hidden="true" />
                  <span className={s.navText}>{item.label}</span>
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className={s.sidebarFoot}>
          <span className={s.status}>
            <span className={s.pulse} />
            Engine online
          </span>
        </div>
      </aside>
      <div className={s.main}>
        <header className={s.topbar}>
          <Button variant="ghost" className={s.mobileToggle} onClick={() => setOpen((o) => !o)} aria-label="Toggle navigation">
            <span className="i-lucide-menu" />
          </Button>
          <span className={s.topbarStatus}>
            <span className={s.pulse} /> WAF active
          </span>
          <div className={s.topbarActions}>
            <IconButton onClick={toggleTheme} aria-label="Toggle theme" title="Toggle theme">
              <span className={theme === 'dark' ? 'i-lucide-sun' : 'i-lucide-moon'} />
            </IconButton>
            <IconButton onClick={clear} aria-label="Sign out" title="Sign out">
              <span className="i-lucide-log-out" />
            </IconButton>
          </div>
        </header>
        <main className={s.content}>{children ?? <Outlet />}</main>
      </div>
    </div>
  )
}
