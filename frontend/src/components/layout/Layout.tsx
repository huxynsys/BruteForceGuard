import { NavLink, Outlet } from 'react-router-dom'
import {
  LayoutDashboard,
  ScrollText,
  ShieldAlert,
  Network,
  ChartLine,
  Settings as SettingsIcon,
  ShieldCheck,
  LifeBuoy,
} from 'lucide-react'
import Topbar from './Topbar'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/events', label: 'Events', icon: ScrollText },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/sessions', label: 'Attack Sessions', icon: Network },
  { to: '/analytics', label: 'Analytics', icon: ChartLine },
]

export default function Layout() {
  return (
    <div className="app">
      <nav className="sidebar" aria-label="Main navigation">
        <div className="brand">
          <span className="brand-mark"><ShieldCheck size={19} aria-hidden="true" /></span>
          <span><strong>BruteForceGuard</strong><small>Threat operations</small></span>
        </div>

        <div className="nav-group-label">Monitor</div>
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `nav-link${isActive ? ' active' : ''}`
            }
          >
            <Icon size={17} aria-hidden="true" />
            {label}
          </NavLink>
        ))}

        <div className="sidebar-separator" role="presentation" />

        <div className="nav-group-label">Workspace</div>

        <NavLink
          to="/settings"
          className={({ isActive }) =>
            `nav-link${isActive ? ' active' : ''}`
          }
        >
          <SettingsIcon size={17} aria-hidden="true" />
          Settings
        </NavLink>

        <div className="sidebar-footer">
          <div className="sidebar-footer-icon"><LifeBuoy size={15} aria-hidden="true" /></div>
          <div><strong>Protection active</strong><span>All collectors online</span></div>
          <span className="status-pulse" aria-label="Online" />
        </div>
      </nav>

      <main className="main">
        <Topbar />
        <Outlet />
      </main>
    </div>
  )
}
