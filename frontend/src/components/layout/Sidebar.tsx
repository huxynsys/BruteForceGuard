import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScrollText,
  AlertTriangle,
  Crosshair,
  BarChart3,
  Settings,
  ShieldCheck,
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/events', label: 'Events', icon: ScrollText },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/sessions', label: 'Attack Sessions', icon: Crosshair },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <ShieldCheck size={20} aria-hidden />
        BruteForceGuard
      </div>

      {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            isActive ? 'nav-item active' : 'nav-item'
          }
        >
          <Icon size={16} aria-hidden />
          {label}
        </NavLink>
      ))}

      <div className="nav-spacer" />
      <div className="nav-divider" />

      <NavLink
        to="/settings"
        className={({ isActive }) =>
          isActive ? 'nav-item active' : 'nav-item'
        }
      >
        <Settings size={16} aria-hidden />
        Settings
      </NavLink>
    </aside>
  )
}
