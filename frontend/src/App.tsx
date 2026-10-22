import { useState } from 'react'
import { Navigate, Outlet, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'
import { AppShell } from '@/components/layout/AppShell'
import { LoginPage } from '@/pages/Login'
import { DashboardPage } from '@/pages/Dashboard'
import { ScannersPage } from '@/pages/Scanners'
import { NewTaskPage } from '@/pages/NewTask'
import { TasksPage } from '@/pages/Tasks'
import { TaskDetailPage } from '@/pages/TaskDetail'
import { FindingsPage } from '@/pages/Findings'
import { WorkflowsPage } from '@/pages/Workflows'
import { TargetsPage } from '@/pages/Targets'
import { ReportsPage } from '@/pages/Reports'
import { SettingsPage } from '@/pages/Settings'
import { EmptyState } from '@/components/ui'
import { Link } from 'react-router-dom'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5_000 },
  },
})

function ProtectedLayout() {
  const { user, ready } = useAuth()
  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-page">
        <div className="flex items-center gap-3 text-sm text-slate-500">
          <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-300 border-t-brand-600" />
          Restoring session…
        </div>
      </div>
    )
  }
  if (!user) return <Navigate to="/login" replace />
  return (
    <WorkspaceProvider>
      <AppShell>
        <Outlet />
      </AppShell>
    </WorkspaceProvider>
  )
}

function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you are looking for does not exist."
      action={
        <Link className="btn-primary" to="/">
          Back to dashboard
        </Link>
      }
    />
  )
}

export default function App() {
  const [ready] = useState(true)
  if (!ready) return null
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<ProtectedLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scanners" element={<ScannersPage />} />
            <Route path="/tasks/new" element={<NewTaskPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/tasks/:id" element={<TaskDetailPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/targets" element={<TargetsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/workflows" element={<WorkflowsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </AuthProvider>
    </QueryClientProvider>
  )
}
