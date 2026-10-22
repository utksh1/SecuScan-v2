import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Play, ShieldAlert, TerminalSquare, ArrowLeft, ChevronDown } from 'lucide-react'
import { request } from '@/api/client'
import type { Plugin, PluginField } from '@/api/types'
import { SafetyBadge } from '@/components/SafetyBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { cn } from '@/utils/format'

export function NewTaskPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [selectedId, setSelectedId] = useState<string>(params.get('plugin') ?? '')
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [preset, setPreset] = useState<string | null>(null)
  const [consent, setConsent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [showPreview, setShowPreview] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['plugins'],
    queryFn: () => request<{ items: Plugin[] }>('/plugins'),
  })
  const plugins = data?.items ?? []
  const startablePlugins = plugins.filter((p) => p.available && p.enabled)
  const plugin = useMemo(
    () => startablePlugins.find((p) => p.id === selectedId) ?? null,
    [startablePlugins, selectedId],
  )

  // Seed form values from defaults / preset when the plugin changes.
  useEffect(() => {
    if (!plugin) return
    const seed: Record<string, string | boolean> = {}
    for (const f of plugin.fields) {
      if (f.default != null) {
        seed[f.id] = typeof f.default === 'boolean' ? f.default : String(f.default)
      }
    }
    setValues(seed)
    setPreset(null)
    setConsent(false)
    setShowPreview(null)
  }, [plugin?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  function applyPreset(name: string) {
    if (!plugin) return
    const p = plugin.presets[name]
    const next = { ...values }
    for (const [k, v] of Object.entries(p ?? {})) {
      next[k] = typeof v === 'boolean' ? v : String(v)
    }
    setValues(next)
    setPreset(name)
  }

  const isViewer = user?.role === 'viewer'

  async function start() {
    if (!plugin) return
    setBusy(true)
    setError(null)
    try {
      const inputs: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(values)) {
        const field = plugin.fields.find((f) => f.id === k)
        if (typeof v === 'boolean') {
          inputs[k] = v
        } else if (v === '') {
          // Empty optional fields are omitted entirely: the backend rejects
          // '' for select/integer fields, and required empties will produce
          // a clearer "missing required field" error.
          if (field?.required) inputs[k] = ''
        } else {
          inputs[k] = v
        }
      }
      const task = await request<{ id: string }>('/tasks', {
        method: 'POST',
        body: {
          plugin_id: plugin.id,
          inputs,
          preset: preset ?? undefined,
          consent_granted: consent,
        },
      })
      navigate(`/tasks/${task.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start task')
    } finally {
      setBusy(false)
    }
  }

  async function preview() {
    if (!plugin) return
    try {
      const inputs: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(values)) {
        if (typeof v === 'boolean') inputs[k] = v
        else if (v !== '') inputs[k] = v
      }
      const body = await request<{ command: string | null }>('/plugins/' + plugin.id + '/preview', {
        method: 'POST',
        body: { inputs, preset: preset ?? undefined },
      })
      setShowPreview(body.command ?? '(no command)')
    } catch (err) {
      setShowPreview(err instanceof Error ? `preview failed: ${err.message}` : 'preview failed')
    }
  }

  const needsConsent = !!plugin?.safety.requires_consent
  const canStart = !!plugin && !isViewer && (!needsConsent || consent) && !busy

  if (isLoading) return <Spinner label="Loading scanners…" />
  if (plugins.length === 0)
    return (
      <EmptyState
        title="No scanners installed"
        description="Add plugin manifests to the plugins/ directory and restart the server."
      />
    )

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div className="flex items-center gap-3">
        <Link to="/scanners" className="btn-ghost -ml-2 px-2" title="Back to scanners">
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <h2 className="text-lg font-semibold text-slate-800">New scan task</h2>
      </div>

      {/* Step 1: pick plugin */}
      <div className="card p-5">
        <div className="mb-2 text-sm font-semibold text-slate-700">1 · Choose a scanner</div>
        <select
          className="input"
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          aria-label="Scanner"
        >
          <option value="">Select a scanner…</option>
          {startablePlugins.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.category})
            </option>
          ))}
        </select>
        {selectedId && !plugin && (
          <p className="mt-2 text-xs text-amber-600">
            This scanner is unavailable or disabled — pick another one.
          </p>
        )}
      </div>

      {plugin && (
        <>
          {/* Step 2: inputs */}
          <div className="card p-5">
            <div className="mb-1 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-700">2 · Configure</div>
              <SafetyBadge level={plugin.safety.level} />
            </div>
            <p className="mb-4 text-xs text-slate-400">{plugin.description}</p>

            {Object.keys(plugin.presets).length > 0 && (
              <div className="mb-4">
                <div className="label">Presets</div>
                <div className="flex flex-wrap gap-1.5">
                  {Object.keys(plugin.presets).map((name) => (
                    <button
                      key={name}
                      type="button"
                      onClick={() => applyPreset(name)}
                      className={cn(
                        'chip capitalize transition-colors',
                        preset === name
                          ? 'bg-brand-600 text-white'
                          : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50',
                      )}
                    >
                      {name}
                    </button>
                  ))}
                </div>
              </div>
            )}

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

            <button type="button" className="btn-secondary mt-4 text-xs" onClick={preview}>
              <TerminalSquare className="h-3.5 w-3.5" /> Preview command
              <ChevronDown className="h-3 w-3" />
            </button>
            {showPreview && (
              <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-200">
                {showPreview}
              </pre>
            )}
          </div>

          {/* Step 3: consent */}
          <div className="card p-5">
            <div className="mb-2 text-sm font-semibold text-slate-700">3 · Authorization</div>
            <label
              className={cn(
                'flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors',
                needsConsent
                  ? consent
                    ? 'border-emerald-200 bg-emerald-50/60'
                    : 'border-amber-200 bg-amber-50/60'
                  : 'border-slate-200 bg-slate-50',
              )}
            >
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 accent-brand-600"
                checked={consent}
                disabled={!needsConsent || isViewer}
                onChange={(e) => setConsent(e.target.checked)}
              />
              <span className="text-sm text-slate-600">
                {needsConsent ? (
                  <>
                    <span className="flex items-center gap-1.5 font-medium text-slate-700">
                      <ShieldAlert className="h-4 w-4 text-amber-600" /> I am authorized to scan
                      this target
                    </span>
                    <span className="mt-1 block text-xs text-slate-500">
                      {plugin.safety.consent_message ??
                        'Only scan systems you own or are explicitly permitted to assess.'}
                    </span>
                    {plugin.safety.allowed_targets.length > 0 && (
                      <span className="mt-1 block font-mono text-[11px] text-slate-400">
                        allowed: {plugin.safety.allowed_targets.join(', ')}
                      </span>
                    )}
                  </>
                ) : (
                  <span className="text-slate-500">
                    This scanner does not require additional consent confirmation.
                  </span>
                )}
              </span>
            </label>
          </div>

          {error && <ErrorNote message={error} />}

          <div className="flex items-center justify-end gap-3">
            {isViewer && (
              <span className="text-xs text-slate-400">Your role is read-only.</span>
            )}
            <button className="btn-primary" onClick={start} disabled={!canStart}>
              <Play className="h-4 w-4" />
              {busy ? 'Starting…' : 'Start scan'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

function FieldInput({
  field,
  value,
  onChange,
}: {
  field: PluginField
  value: string | boolean | undefined
  onChange: (v: string | boolean) => void
}) {
  const wide = field.type === 'text' || field.type === 'select'
  return (
    <div className={wide ? 'sm:col-span-2' : undefined}>
      <label htmlFor={`f-${field.id}`} className="label">
        {field.label}
        {field.required && <span className="ml-1 text-rose-500">*</span>}
      </label>
      {field.type === 'boolean' ? (
        <label className="flex cursor-pointer items-center gap-2 py-1.5">
          <input
            id={`f-${field.id}`}
            type="checkbox"
            className="h-4 w-4 accent-brand-600"
            checked={typeof value === 'boolean' ? value : false}
            onChange={(e) => onChange(e.target.checked)}
          />
          <span className="text-sm text-slate-600">{field.help ?? 'Enabled'}</span>
        </label>
      ) : field.type === 'select' ? (
        <select
          id={`f-${field.id}`}
          className="input"
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">—</option>
          {field.options?.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      ) : field.type === 'text' ? (
        <textarea
          id={`f-${field.id}`}
          className="input min-h-[80px]"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          id={`f-${field.id}`}
          className="input"
          type={field.type === 'integer' ? 'number' : 'text'}
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          min={field.type === 'integer' ? field.min : undefined}
          max={field.type === 'integer' ? field.max : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {field.help && field.type !== 'boolean' && (
        <p className="mt-1 text-xs text-slate-400">{field.help}</p>
      )}
    </div>
  )
}
