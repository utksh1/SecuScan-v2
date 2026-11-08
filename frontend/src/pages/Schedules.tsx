// Schedules: recurring scans with interval presets, live run-now, enable
// toggles and last-run visibility (pentest-tools.com "schedule scans").

import { useEffect, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import {
  CalendarClock,
  CalendarPlus,
  Play,
  Trash2,
  Pencil,
  ShieldAlert,
  X,
} from 'lucide-react'
import { request, scheduleApi } from '@/api/client'
import type { Plugin, Schedule } from '@/api/types'
import { FieldInput } from '@/components/FieldInput'
import { SafetyBadge } from '@/components/SafetyBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'
import { cn, formatDate } from '@/utils/format'

// Interval presets (seconds). Custom values are entered in minutes.
const INTERVAL_PRESETS: { label: string; seconds: number }[] = [
  { label: 'every 15 minutes', seconds: 15 * 60 },
  { label: 'every hour', seconds: 3600 },
  { label: 'every 6 hours', seconds: 6 * 3600 },
  { label: 'every 12 hours', seconds: 12 * 3600 },
  { label: 'every day', seconds: 24 * 3600 },
  { label: 'every week', seconds: 7 * 24 * 3600 },
  { label: 'every 30 days', seconds: 30 * 24 * 3600 },
]

export function formatInterval(seconds: number): string {
  const preset = INTERVAL_PRESETS.find((p) => p.seconds === seconds)
  if (preset) return preset.label
  if (seconds % 86_400 === 0) return `every ${seconds / 86_400}d`
  if (seconds % 3_600 === 0) return `every ${seconds / 3_600}h`
  if (seconds % 60 === 0) return `every ${seconds / 60}m`
  return `every ${seconds}s`
}

export function SchedulesPage() {
  const { user } = useAuth()
  const { workspaces } = useWorkspace()
  const queryClient = useQueryClient()
  const [params] = useSearchParams()
  const [editing, setEditing] = useState<Schedule | null>(null)
  const [creating, setCreating] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const schedulesQuery = useQuery({
    queryKey: ['schedules'],
    queryFn: () => scheduleApi.list(),
    // Light polling so next-run / last-run stay fresh.
    refetchInterval: 15_000,
  })

  const toggle = useMutation({
    mutationFn: (s: Schedule) => scheduleApi.update(s.id, { enabled: !s.enabled }),
    onSuccess: () => setActionError(null),
    onError: (e) => setActionError(e instanceof Error ? e.message : 'Failed to update schedule'),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const runNow = useMutation({
    mutationFn: (s: Schedule) => scheduleApi.runNow(s.id),
    onSuccess: () => setActionError(null),
    onError: (e) => setActionError(e instanceof Error ? e.message : 'Failed to run now'),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const remove = useMutation({
    mutationFn: (s: Schedule) => scheduleApi.remove(s.id),
    onSuccess: () => setActionError(null),
    onError: (e) => setActionError(e instanceof Error ? e.message : 'Failed to delete schedule'),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const isViewer = user?.role === 'viewer'

  // Deep link: /schedules?create=1&plugin=<id>&target=<name>
  useEffect(() => {
    if (params.get('create') === '1') setCreating(true)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (schedulesQuery.isLoading) return <Spinner label="Loading schedules…" />
  if (schedulesQuery.error)
    return (
      <ErrorNote
        message={
          schedulesQuery.error instanceof Error
            ? schedulesQuery.error.message
            : 'Failed to load schedules'
        }
      />
    )

  const schedules = schedulesQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Schedules</h2>
          <p className="mt-0.5 text-sm text-slate-500">
            Recurring scans launched automatically by the server; every run passes the
            full admission pipeline (policy, consent, plugin availability).
          </p>
        </div>
        {!isViewer && !creating && !editing && (
          <button className="btn-primary" onClick={() => setCreating(true)}>
            <CalendarPlus className="h-4 w-4" /> New schedule
          </button>
        )}
      </div>

      {(creating || editing) && (
        <ScheduleForm
          schedule={editing}
          workspaces={workspaces}
          defaultPlugin={params.get('plugin') ?? undefined}
          defaultTarget={params.get('target') ?? undefined}
          onDone={() => {
            setCreating(false)
            setEditing(null)
            queryClient.invalidateQueries({ queryKey: ['schedules'] })
          }}
        />
      )}

      {actionError && <ErrorNote message={actionError} />}

      <div className="card">
        {schedules.length === 0 ? (
          <EmptyState
            icon={<CalendarClock className="h-8 w-8 text-slate-400" />}
            title="No schedules"
            description="Create a schedule to run a scanner against a target automatically — daily port scans, weekly TLS checks, and so on."
            action={
              !isViewer ? (
                <button className="btn-primary" onClick={() => setCreating(true)}>
                  <CalendarPlus className="h-4 w-4" /> New schedule
                </button>
              ) : undefined
            }
          />
        ) : (
          <SchedulesTable
            schedules={schedules}
            isViewer={isViewer}
            onToggle={(s) => toggle.mutate(s)}
            onRun={(s) => runNow.mutate(s)}
            onEdit={(s) => {
              setCreating(false)
              setEditing(s)
            }}
            onDelete={(s) => remove.mutate(s)}
            pendingRun={runNow.isPending}
          />
        )}
      </div>
    </div>
  )
}

function SchedulesTable({
  schedules,
  isViewer,
  onToggle,
  onRun,
  onEdit,
  onDelete,
  pendingRun,
}: {
  schedules: Schedule[]
  isViewer: boolean
  onToggle: (s: Schedule) => void
  onRun: (s: Schedule) => void
  onEdit: (s: Schedule) => void
  onDelete: (s: Schedule) => void
  pendingRun: boolean
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-400">
            <th className="px-4 py-3 font-medium">Name</th>
            <th className="px-4 py-3 font-medium">Scanner / target</th>
            <th className="px-4 py-3 font-medium">Interval</th>
            <th className="px-4 py-3 font-medium">Next run</th>
            <th className="px-4 py-3 font-medium">Last run</th>
            <th className="px-4 py-3 font-medium">Enabled</th>
            {!isViewer && <th className="px-4 py-3" />}
          </tr>
        </thead>
        <tbody>
          {schedules.map((s) => (
            <tr key={s.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/60">
              <td className="px-4 py-3">
                <div className="font-medium text-slate-800">{s.name}</div>
                {s.last_error && (
                  <div
                    className="mt-0.5 max-w-xs truncate text-xs text-rose-600"
                    title={s.last_error}
                  >
                    last attempt rejected: {s.last_error}
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                <div className="font-mono text-xs text-slate-600">{s.plugin_id}</div>
                <div className="mt-0.5 max-w-[220px] truncate font-mono text-xs text-slate-400">
                  {s.target ?? '—'}
                </div>
              </td>
              <td className="px-4 py-3 text-slate-600">{formatInterval(s.interval_seconds)}</td>
              <td className="px-4 py-3 text-slate-600">
                {s.enabled ? formatDate(s.next_run_at) : <span className="text-slate-400">paused</span>}
              </td>
              <td className="px-4 py-3">
                {s.last_run_at ? (
                  <span className="text-slate-600">
                    {formatDate(s.last_run_at)}
                    {s.last_task_id && (
                      <>
                        {' · '}
                        <Link
                          className="text-brand-600 hover:underline"
                          to={`/tasks/${s.last_task_id}`}
                        >
                          task
                        </Link>
                      </>
                    )}
                  </span>
                ) : (
                  <span className="text-slate-400">never</span>
                )}
              </td>
              <td className="px-4 py-3">
                <button
                  role="switch"
                  aria-checked={s.enabled}
                  aria-label={`Toggle ${s.name}`}
                  disabled={isViewer}
                  onClick={() => onToggle(s)}
                  className={cn(
                    'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors',
                    s.enabled ? 'bg-brand-600' : 'bg-slate-300',
                    isViewer && 'opacity-50',
                  )}
                >
                  <span
                    className={cn(
                      'inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform',
                      s.enabled ? 'translate-x-[18px]' : 'translate-x-1',
                    )}
                  />
                </button>
              </td>
              {!isViewer && (
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      className="btn-ghost px-2 py-1 text-xs"
                      title="Run now (does not affect the recurring cadence)"
                      disabled={pendingRun}
                      onClick={() => onRun(s)}
                    >
                      <Play className="h-3.5 w-3.5" /> Run now
                    </button>
                    <button
                      className="btn-ghost px-2 py-1 text-xs"
                      title="Edit schedule"
                      onClick={() => onEdit(s)}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      className="btn-ghost px-2 py-1 text-xs text-rose-600 hover:text-rose-700"
                      title="Delete schedule (past tasks are kept)"
                      onClick={() => onDelete(s)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Create / edit form
// ---------------------------------------------------------------------------

function ScheduleForm({
  schedule,
  workspaces,
  defaultPlugin,
  defaultTarget,
  onDone,
}: {
  schedule: Schedule | null
  workspaces: { id: string; name: string }[]
  defaultPlugin?: string
  defaultTarget?: string
  onDone: () => void
}) {
  const pluginsQuery = useQuery({
    queryKey: ['plugins'],
    queryFn: () => request<{ items: Plugin[] }>('/plugins'),
  })
  const plugins = pluginsQuery.data?.items ?? []
  const startable = plugins.filter((p) => p.available && p.enabled)

  const [name, setName] = useState(schedule?.name ?? '')
  const [selectedId, setSelectedId] = useState(schedule?.plugin_id ?? defaultPlugin ?? '')
  const [values, setValues] = useState<Record<string, string | boolean>>(() => {
    if (!schedule) return {}
    const seed: Record<string, string | boolean> = {}
    for (const [k, v] of Object.entries(schedule.inputs)) {
      seed[k] = typeof v === 'boolean' ? v : String(v)
    }
    return seed
  })
  const [intervalSeconds, setIntervalSeconds] = useState(
    schedule?.interval_seconds ?? 24 * 3600,
  )
  // Sprint 2.2 (#25): named frequencies override the raw interval.
  const [frequency, setFrequency] = useState<string>(schedule?.frequency ?? '')
  const [anchorTime, setAnchorTime] = useState<string>(schedule?.anchor_time ?? '09:00')
  const [tz, setTz] = useState<string>(schedule?.tz ?? 'UTC')
  const [customMinutes, setCustomMinutes] = useState<string>(() =>
    // Editing a schedule with a non-preset interval: prefill the custom
    // minutes so saving unchanged round-trips the same value (otherwise
    // an empty input would submit interval_seconds = 0 and be rejected).
    schedule && !INTERVAL_PRESETS.some((p) => p.seconds === schedule.interval_seconds)
      ? String(Math.round(schedule.interval_seconds / 60))
      : '',
  )
  const [workspaceId, setWorkspaceId] = useState<string>(schedule?.workspace_id ?? '')
  const [consent, setConsent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const plugin = useMemo(
    () => startable.find((p) => p.id === selectedId) ?? null,
    [startable, selectedId],
  )

  // Seed form values from defaults when the plugin changes (create mode).
  // The ?target= prefill is folded into the seed (not a separate effect) so
  // it survives regardless of whether the plugins query resolves before or
  // after mount — a standalone effect would be wiped by this seed.
  useEffect(() => {
    if (!plugin || schedule) return
    const seed: Record<string, string | boolean> = {}
    for (const f of plugin.fields) {
      if (f.default != null) {
        seed[f.id] = typeof f.default === 'boolean' ? f.default : String(f.default)
      }
    }
    if (defaultTarget) seed.target = defaultTarget
    setValues(seed)
    setConsent(false)
  }, [plugin?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const isCustom = !INTERVAL_PRESETS.some((p) => p.seconds === intervalSeconds)
  const needsConsent = !!plugin?.safety.requires_consent

  // The interval actually submitted: preset seconds, or custom minutes.
  // NaN / empty / < 5min all fail the bound here instead of server-side.
  const effectiveSeconds = isCustom
    ? Math.round(Number(customMinutes) * 60)
    : intervalSeconds

  const canSubmit =
    !!plugin &&
    name.trim().length > 0 &&
    Number.isFinite(effectiveSeconds) &&
    effectiveSeconds >= 300 &&
    (!needsConsent || consent) &&
    !busy

  async function submit() {
    if (!plugin) return
    setBusy(true)
    setError(null)
    try {
      const inputs: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(values)) {
        const field = plugin.fields.find((f) => f.id === k)
        if (typeof v === 'boolean') inputs[k] = v
        else if (v === '') {
          if (field?.required) inputs[k] = ''
        } else inputs[k] = v
      }
      const seconds = isCustom ? Math.round(Number(customMinutes) * 60) : intervalSeconds
      if (frequency === '' && (!Number.isFinite(seconds) || seconds < 300)) {
        setError('Interval must be at least 5 minutes.')
        return
      }
      const cadence = frequency
        ? {
            frequency,
            anchor_time: anchorTime,
            tz,
          }
        : {}
      void cadence
      if (schedule) {
        await scheduleApi.update(schedule.id, {
          name: name.trim(),
          inputs,
          preset: schedule.preset ?? null,
          interval_seconds: seconds,
          workspace_id: workspaceId || null,
          ...(frequency ? { frequency, anchor_time: anchorTime, tz } : {}),
        })
      } else {
        await scheduleApi.create({
          name: name.trim(),
          plugin_id: plugin.id,
          inputs,
          interval_seconds: seconds,
          consent_granted: consent,
          ...(workspaceId ? { workspace_id: workspaceId } : {}),
          ...(frequency ? { frequency, anchor_time: anchorTime, tz } : {}),
        })
      }
      onDone()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save schedule')
    } finally {
      setBusy(false)
    }
  }

  if (pluginsQuery.isLoading) return <Spinner label="Loading scanners…" />

  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-700">
                          {schedule ? `Edit “${schedule.name}”` : 'New schedule'}
        </div>
        <button className="btn-ghost px-2" onClick={onDone} aria-label="Close form">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="sched-name">
            Name <span className="text-rose-500">*</span>
          </label>
          <input
            id="sched-name"
            className="input"
            placeholder="Daily port sweep"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label className="label" htmlFor="sched-plugin">
            Scanner <span className="text-rose-500">*</span>
          </label>
          <select
            id="sched-plugin"
            className="input"
            value={selectedId}
            disabled={!!schedule}
            onChange={(e) => setSelectedId(e.target.value)}
          >
            <option value="">Select a scanner…</option>
            {startable.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.category})
              </option>
            ))}
          </select>
          {schedule && (
            <p className="mt-1 text-xs text-slate-400">
              The scanner of an existing schedule cannot be changed.
            </p>
          )}
        </div>
        <div>
          <label className="label" htmlFor="sched-frequency">
            Cadence
          </label>
          <select
            id="sched-frequency"
            className="input"
            value={frequency}
            onChange={(e) => setFrequency(e.target.value)}
          >
            <option value="">Custom interval (below)</option>
            <option value="hourly">Hourly</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
            <option value="quarterly">Quarterly</option>
            <option value="once">Once (then disabled)</option>
          </select>
          {frequency !== '' && (
            <div className="mt-2 grid grid-cols-2 gap-2">
              <input
                className="input"
                type="time"
                value={anchorTime}
                onChange={(e) => setAnchorTime(e.target.value)}
                aria-label="Anchor time"
              />
              <input
                className="input"
                value={tz}
                onChange={(e) => setTz(e.target.value)}
                aria-label="Timezone (IANA)"
                placeholder="UTC"
              />
            </div>
          )}
          {frequency !== '' && (
            <p className="mt-1 text-xs text-slate-400">
              Runs at {anchorTime} ({tz}) with the chosen cadence. Monthly runs
              clamp to the month&apos;s last day.
            </p>
          )}
        </div>
        <div>
          <label className="label" htmlFor="sched-interval">
            Interval {frequency === '' && <span className="text-rose-500">*</span>}
          </label>
          <select
            id="sched-interval"
            className={cn('input', frequency !== '' && 'opacity-50 pointer-events-none')}
            value={isCustom ? 'custom' : String(intervalSeconds)}
            onChange={(e) => {
              if (e.target.value !== 'custom') setIntervalSeconds(Number(e.target.value))
              else if (!customMinutes) setCustomMinutes('30')
            }}
          >
            {INTERVAL_PRESETS.map((p) => (
              <option key={p.seconds} value={p.seconds}>
                {p.label}
              </option>
            ))}
            <option value="custom">custom…</option>
          </select>
          {isCustom && (
            <input
              className="input mt-2"
              type="number"
              min={5}
              aria-label="Custom interval in minutes"
              placeholder="minutes (min 5)"
              value={customMinutes}
              onChange={(e) => setCustomMinutes(e.target.value)}
            />
          )}
          <p className="mt-1 text-xs text-slate-400">
            Minimum 5 minutes. Missed occurrences are skipped, not replayed.
          </p>
        </div>
        <div>
          <label className="label" htmlFor="sched-workspace">
            Workspace
          </label>
          <select
            id="sched-workspace"
            className="input"
            value={workspaceId}
            onChange={(e) => setWorkspaceId(e.target.value)}
          >
            <option value="">Personal (no workspace)</option>
            {workspaces.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {plugin && (
        <div className="mt-4">
          <div className="mb-2 flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-700">Scanner inputs</div>
            <SafetyBadge level={plugin.safety.level} />
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {plugin.fields.map((f) => (
              <FieldInput
                key={f.id}
                field={f}
                value={values[f.id]}
                onChange={(v) => setValues((prev) => ({ ...prev, [f.id]: v }))}
              />
            ))}
          </div>
        </div>
      )}

      {plugin && needsConsent && !schedule && (
        <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border border-amber-200 bg-amber-50/60 p-4">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 accent-brand-600"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
          />
          <span className="text-sm text-slate-600">
            <span className="flex items-center gap-1.5 font-medium text-slate-700">
              <ShieldAlert className="h-4 w-4 text-amber-600" /> I am authorized to scan this
              target on a recurring basis
            </span>
            <span className="mt-1 block text-xs text-slate-500">
              {plugin.safety.consent_message ??
                'Only schedule scans of systems you own or are explicitly permitted to assess.'}
            </span>
          </span>
        </label>
      )}

      {error && (
        <div className="mt-4">
          <ErrorNote message={error} />
        </div>
      )}

      <div className="mt-5 flex items-center justify-end gap-3">
        <button className="btn-secondary" onClick={onDone} disabled={busy}>
          Cancel
        </button>
        <button className="btn-primary" onClick={submit} disabled={!canSubmit}>
          <CalendarPlus className="h-4 w-4" />
          {busy ? 'Saving…' : schedule ? 'Save changes' : 'Create schedule'}
        </button>
      </div>
    </div>
  )
}
