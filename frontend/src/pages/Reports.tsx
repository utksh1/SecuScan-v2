// Reports: async report-job history with live status polling, artifact
// downloads, and webhook delivery visibility.

import { useQuery } from '@tanstack/react-query'
import { FileText, ListTodo } from 'lucide-react'
import { Link } from 'react-router-dom'
import { reportApi } from '@/api/client'
import { ReportJobsTable } from '@/components/ReportJobsTable'
import { EmptyState, ErrorNote, Spinner } from '@/components/ui'

export function ReportsPage() {
  const jobsQuery = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportApi.list(),
    // Poll while anything is still rendering; settle once all are terminal.
    refetchInterval: (query) => {
      const active = query.state.data?.items.some(
        (j) => j.status === 'waiting' || j.status === 'in_progress',
      )
      return active ? 2000 : false
    },
  })

  if (jobsQuery.isLoading) return <Spinner label="Loading report jobs…" />
  if (jobsQuery.error)
    return <ErrorNote message={jobsQuery.error instanceof Error ? jobsQuery.error.message : 'Failed to load report jobs'} />

  const jobs = jobsQuery.data?.items ?? []
  const active = jobs.filter((j) => j.status === 'waiting' || j.status === 'in_progress').length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Report jobs</h2>
          <p className="mt-0.5 text-sm text-slate-500">
            Background report generation with signed webhook callbacks.
            {active > 0 && (
              <span className="ml-1 text-blue-600">
                {active} rendering — refreshing every 2s.
              </span>
            )}
          </p>
        </div>
      </div>

      <div className="card">
        {jobs.length === 0 ? (
          <EmptyState
            icon={<ListTodo className="h-8 w-8 text-slate-400" />}
            title="No report jobs"
            description="Open a completed task and use its Reports tab to generate PDF, DOCX, XLSX, SARIF and other formats in the background."
            action={
              <Link className="btn-secondary" to="/tasks">
                <FileText className="h-4 w-4" /> Browse tasks
              </Link>
            }
          />
        ) : (
          <ReportJobsTable jobs={jobs} />
        )}
      </div>
    </div>
  )
}
