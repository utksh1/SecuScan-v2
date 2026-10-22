import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Blocks,
  ListChecks,
  ShieldAlert,
  GitBranch,
  Settings,
  CirclePlus,
  LogOut,
  ShieldCheck,
} from 'lucide-react'
import { useAuth } from '@/auth/AuthContext'
import { cn } from '@/utils/format'
import type { ReactNode } from 'react'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/scanners', label: 'Scanners', icon: Blocks },
  { to: '/tasks/new', label: 'New Task', icon: CirclePlus },
  { to: '/tasks', label: 'Tasks', icon: ListChecks, end: true },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/workflows', label: 'Workflows', icon: GitBranch },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const pageTitle =
    NAV.find((n) => (n.end ? n.to === location.pathname : location.pathname.startsWith(n.to)))
      ?.label ?? 'SecuScan'

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 flex w-60 flex-col bg-surface-sidebar text-slate-300">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600/20">
            <ShieldCheck className="h-5 w-5 text-brand-400" />
          </span>
          <div>
            <div className="text-base font-semibold tracking-tight text-white">SecuScan</div>
            <div className="text-[11px] text-slate-500">v2 · security workspace</div>
          </div>
        </div>

        <nav className="mt-2 flex-1 space-y-1 px-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-brand-600/20 text-white'
                    : 'text-slate-400 hover:bg-surface-sidebar-hover hover:text-slate-100',
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-slate-800 p-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-slate-800 text-sm font-semibold text-brand-300">
              {(user?.name ?? '?').slice(0, 1).toUpperCase()}
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium text-slate-200">{user?.name}</div>
              <div className="truncate text-xs capitalize text-slate-500">{user?.role}</div>
            </div>
            <button
              title="Sign out"
              onClick={async () => {
                await logout()
                navigate('/login')
              }}
              className="rounded-lg p-2 text-slate-500 transition-colors hover:bg-slate-800 hover:text-slate-200"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Content */}
      <div className="ml-60 flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-200 bg-white/80 px-6 backdrop-blur">
          <h1 className="text-sm font-semibold text-slate-800">{pageTitle}</h1>
          <div className="text-xs text-slate-400">
            Authorized use only · <span className="text-slate-500">{user?.email}</span>
          </div>
        </header>
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  )
}
