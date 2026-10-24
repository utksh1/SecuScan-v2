import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import {
  Play,
  ShieldAlert,
  TerminalSquare,
  ArrowLeft,
  ChevronDown,
  Zap,
  Layers,
  EyeOff,
  Gauge,
  SlidersHorizontal,
  Clock,
  Network,
  Globe,
  Search,
  Crosshair,
  Cloud,
  Boxes,
} from 'lucide-react'
import { request, workspaceApi } from '@/api/client'
import type { Plugin } from '@/api/types'
import { SafetyBadge } from '@/components/SafetyBadge'
import { FieldInput } from '@/components/FieldInput'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'
import { cn } from '@/utils/format'

// Badge token -> (icon, human label, chip classes). Presets without a
// badge (or with an unknown one) fall back to the neutral style.
const BADGE_STYLES: Record<
  string,
  { icon: typeof Zap; label: string; chip: string }
> = {
  fast: {
    icon: Zap,
    label: 'fast',
    chip: 'bg-sky-50 text-sky-700 ring-sky-200',
  },
  thorough: {
    icon: Layers,
    label: 'thorough',
    chip: 'bg-violet-50 text-violet-700 ring-violet-200',
  },
  intense: {
    icon: Gauge,
    label: 'intense',
    chip: 'bg-rose-50 text-rose-700 ring-rose-200',
  },
  stealth: {
    icon: EyeOff,
    label: 'stealth',
    chip: 'bg-slate-100 text-slate-600 ring-slate-300',
  },
}

// v4.2.2: badge-derived estimated-runtime hints shown on profile cards.
// The ranges are honest ballparks, not SLAs: a `fast` profile against a
// slow host can still take minutes, and a `stealth` profile is slow by
// design (T1 timing, paced requests).
const BADGE_ETA: Record<string, string> = {
  fast: 'est. seconds – a few minutes',
  thorough: 'est. a few minutes',
  intense: 'est. 10+ minutes',
  stealth: 'est. slow by design (low & slow)',
}

// v4.2.2: presentation metadata for the category-grouped scanner
// browser. Unknown categories fall back to a generic icon + the raw
// category string.
const CATEGORY_ORDER = ['network', 'web', 'recon', 'exploitation', 'cloud']
const CATEGORY_META: Record<string, { icon: typeof Zap; label: string }> = {
  network: { icon: Network, label: 'Network' },
  web: { icon: Globe, label: 'Web' },
  recon: { icon: Search, label: 'Recon' },
  exploitation: { icon: Crosshair, label: 'Exploitation' },
  cloud: { icon: Cloud, label: 'Cloud' },
}

function categoryMeta(category: string) {
  return (
    CATEGORY_META[category] ?? {
      icon: Boxes,
      label: category.charAt(0).toUpperCase() + category.slice(1),
    }
  )
}

function presetLabel(name: string, meta?: { label?: string }) {
  return meta?.label ?? name.replace(/(^|-)([a-z])/g, (_, sep, c) => (sep ? ' ' : '') + c.toUpperCase())
}

export function NewTaskPage() {
  const [params] = useSearchParams()
  const { current, workspaces, select } = useWorkspace()
  const [useWorkspaceScope, setUseWorkspaceScope] = useState(false)
  const navigate = useNavigate()
  const { user } = useAuth()
  const [selectedId, setSelectedId] = useState<string>(params.get('plugin') ?? '')
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [preset, setPreset] = useState<string | null>(null)
  // v4.2.2: profile chip clicked in the category browser for a scanner
  // that is not selected yet. The seed effect applies it once the plugin
  // switch lands (it re-seeds defaults on every plugin change, so the
  // pending preset must ride along or it would be wiped).
  const [pendingPreset, setPendingPreset] = useState<string | null>(null)
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

  // v4.2.2: the category-grouped scanner browser — startable scanners
  // bucketed by category, known categories first, then the rest
  // alphabetically.
  const categoryGroups = useMemo(() => {
    const groups = new Map<string, Plugin[]>()
    for (const p of startablePlugins) {
      const list = groups.get(p.category) ?? []
      list.push(p)
      groups.set(p.category, list)
    }
    for (const list of groups.values()) list.sort((a, b) => a.name.localeCompare(b.name))
    return [...groups.entries()].sort((a, b) => {
      const ai = CATEGORY_ORDER.indexOf(a[0])
      const bi = CATEGORY_ORDER.indexOf(b[0])
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a[0].localeCompare(b[0])
    })
  }, [startablePlugins]) // eslint-disable-line react-hooks/exhaustive-deps

  // Registered targets of the selected workspace, offered as quick picks
  // for the primary target field.
  const targetsQuery = useQuery({
    queryKey: ['targets', current?.id ?? 'personal'],
    queryFn: () => workspaceApi.targets(current!.id),
    enabled: !!current,
  })
  const registeredTargets = targetsQuery.data?.items ?? []

  // Default the workspace toggle to "on" when the user arrived via the
  // sidebar with a non-Personal workspace selected.
  useEffect(() => {
    if (current) setUseWorkspaceScope(true)
  }, [current?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  // ?target=<name> prefill (e.g. "Scan" button on the Targets page).
  const targetPrefill = params.get('target')
  const plugin = useMemo(
    () => startablePlugins.find((p) => p.id === selectedId) ?? null,
    [startablePlugins, selectedId],
  )

  // Seed form values from defaults / preset when the plugin changes. The
  // ?target= prefill is folded into the seed (not a separate effect) so it
  // survives regardless of whether the plugins query resolves before or
  // after mount — a standalone effect would be wiped by this seed.
  // v4.2.2: a pending profile-chip jump (from the category browser) is
  // applied on top of the fresh defaults, exactly as if the user had
  // clicked the profile card right after the switch.
  useEffect(() => {
    if (!plugin) return
    const seed: Record<string, string | boolean> = {}
    for (const f of plugin.fields) {
      if (f.default != null) {
        seed[f.id] = typeof f.default === 'boolean' ? f.default : String(f.default)
      }
    }
    if (targetPrefill) seed.target = targetPrefill
    const pending =
      pendingPreset && plugin.presets[pendingPreset] ? pendingPreset : null
    if (pending) {
      for (const [k, v] of Object.entries(plugin.presets[pending])) {
        seed[k] = typeof v === 'boolean' ? v : String(v)
      }
    }
    setValues(seed)
    setPreset(pending)
    setPendingPreset(null)
    setConsent(false)
    setShowPreview(null)
  }, [plugin?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  function applyPreset(name: string | null) {
    if (!plugin) return
    if (name === null) {
      // "Custom" — restore the plain defaults so the manual field
      // configuration starts from a clean slate.
      const seed: Record<string, string | boolean> = {}
      for (const f of plugin.fields) {
        if (f.default != null) {
          seed[f.id] = typeof f.default === 'boolean' ? f.default : String(f.default)
        }
      }
      if (targetPrefill) seed.target = targetPrefill
      setValues((prev) => ({ ...seed, target: prev.target ?? seed.target ?? '' }))
      setPreset(null)
      return
    }
    const p = plugin.presets[name]
    const next = { ...values }
    for (const [k, v] of Object.entries(p ?? {})) {
      next[k] = typeof v === 'boolean' ? v : String(v)
    }
    setValues(next)
    setPreset(name)
  }

  // v4.2.2: jump straight from a category-browser profile chip into the
  // configured task. When the scanner is already selected this is just
  // applyPreset; otherwise the plugin switch is queued together with the
  // preset so the seed effect can apply it after it re-seeds defaults.
  function jumpToProfile(pluginId: string, presetName: string) {
    if (pluginId === selectedId) {
      applyPreset(presetName)
    } else {
      setSelectedId(pluginId)
      setPendingPreset(presetName)
    }
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
          ...(useWorkspaceScope && current ? { workspace_id: current.id } : {}),
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
          {categoryGroups.map(([cat, list]) => (
            <optgroup key={cat} label={categoryMeta(cat).label}>
              {list.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {selectedId && !plugin && (
          <p className="mt-2 text-xs text-amber-600">
            This scanner is unavailable or disabled — pick another one.
          </p>
        )}

        {/* v4.2.2: category-grouped scanner browser. Every scanner's scan
            profiles are surfaced as chips — click a chip to jump straight
            into the configured task (scanner selected + profile applied). */}
        {categoryGroups.length > 0 && (
          <div
            role="group"
            aria-label="Browse scanners by category"
            className="mt-4"
          >
            <div className="mb-2 flex items-center justify-between">
              <span className="label mb-0">Browse by category</span>
              <span className="text-[11px] text-slate-400">
                click a profile chip to jump straight in
              </span>
            </div>
            <div className="max-h-80 space-y-3 overflow-y-auto pr-1">
              {categoryGroups.map(([cat, list]) => {
                const meta = categoryMeta(cat)
                const CatIcon = meta.icon
                return (
                  <div key={cat}>
                    <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                      <CatIcon className="h-3.5 w-3.5" />
                      {meta.label}
                      <span className="font-normal text-slate-400">({list.length})</span>
                    </div>
                    <div className="grid grid-cols-1 gap-1.5 lg:grid-cols-2">
                      {list.map((p) => {
                        const presetNames = Object.keys(p.presets)
                        const selected = p.id === selectedId
                        return (
                          <div
                            key={p.id}
                            className={cn(
                              'flex items-center gap-1.5 rounded-lg border px-2 py-1.5 transition-colors',
                              selected
                                ? 'border-brand-500 bg-brand-50/70 ring-1 ring-brand-500'
                                : 'border-slate-200 bg-white hover:border-slate-300',
                            )}
                          >
                            <button
                              type="button"
                              onClick={() => setSelectedId(p.id)}
                              aria-label={`Select ${p.name}`}
                              className="min-w-0 flex-1 truncate text-left text-sm text-slate-700"
                              title={p.description}
                            >
                              {p.name}
                            </button>
                            {presetNames.length > 0 ? (
                              <span className="flex shrink-0 flex-wrap justify-end gap-1">
                                {presetNames.map((name) => {
                                  const pm = p.preset_meta?.[name]
                                  const badge = pm?.badge
                                    ? BADGE_STYLES[pm.badge]
                                    : undefined
                                  const eta = pm?.badge ? BADGE_ETA[pm.badge] : undefined
                                  return (
                                    <button
                                      key={name}
                                      type="button"
                                      onClick={() => jumpToProfile(p.id, name)}
                                      aria-label={`${p.name}: ${presetLabel(name, pm)} profile`}
                                      title={
                                        [pm?.description, eta].filter(Boolean).join(' · ') ||
                                        `Run the ${presetLabel(name, pm)} profile`
                                      }
                                      className={cn(
                                        'rounded px-1.5 py-0.5 text-[10px] font-medium ring-1 transition-transform hover:scale-[1.04]',
                                        badge
                                          ? badge.chip
                                          : 'bg-slate-100 text-slate-600 ring-slate-200',
                                      )}
                                    >
                                      {presetLabel(name, pm)}
                                    </button>
                                  )
                                })}
                              </span>
                            ) : (
                              <span
                                className="shrink-0 rounded bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-400 ring-1 ring-slate-200"
                                title="This scanner has no scan profiles — configure it manually"
                              >
                                manual
                              </span>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {plugin && (
        <>
          {/* Step 1.5: workspace + registered target quick-pick */}
          <div className="card p-5">
            <div className="mb-2 text-sm font-semibold text-slate-700">Workspace</div>
            <div className="flex flex-wrap items-center gap-3">
              <select
                className="input max-w-xs"
                aria-label="Workspace"
                value={useWorkspaceScope && current ? current.id : ''}
                onChange={(e) => {
                  const id = e.target.value
                  if (!id) {
                    setUseWorkspaceScope(false)
                  } else {
                    setUseWorkspaceScope(true)
                    if (id !== current?.id) select(id)
                  }
                }}
              >
                <option value="">Personal (no workspace)</option>
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))}
              </select>
              {registeredTargets.length > 0 && (
                <div className="flex min-w-[220px] flex-1 items-center gap-2">
                  <label className="whitespace-nowrap text-xs font-medium text-slate-600">
                    Registered targets
                  </label>
                  <select
                    className="input"
                    aria-label="Registered targets"
                    value=""
                    onChange={(e) => {
                      if (e.target.value)
                        setValues((prev) => ({ ...prev, target: e.target.value }))
                    }}
                  >
                    <option value="">Pick a target…</option>
                    {registeredTargets.map((t) => (
                      <option key={t.id} value={t.name}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            <p className="mt-2 text-xs text-slate-400">
              Tasks filed under a workspace are grouped with its targets in Tasks, Findings and
              the dashboard.
            </p>
          </div>

          {/* Step 2: inputs */}
          <div className="card p-5">
            <div className="mb-1 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-700">2 · Configure</div>
              <SafetyBadge level={plugin.safety.level} />
            </div>
            <p className="mb-4 text-xs text-slate-400">{plugin.description}</p>

            {Object.keys(plugin.presets).length > 0 && (
              <div className="mb-4" role="group" aria-label="Scan profile">
                <div className="label">Scan profile</div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {Object.entries(plugin.presets).map(([name, values]) => {
                    const meta = plugin.preset_meta?.[name]
                    const badge = meta?.badge ? BADGE_STYLES[meta.badge] : undefined
                    const BadgeIcon = badge?.icon ?? Layers
                    const eta = meta?.badge ? BADGE_ETA[meta.badge] : undefined
                    return (
                      <button
                        key={name}
                        type="button"
                        onClick={() => applyPreset(name)}
                        className={cn(
                          'flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors',
                          preset === name
                            ? 'border-brand-500 bg-brand-50/70 ring-1 ring-brand-500'
                            : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50',
                        )}
                      >
                        <span
                          className={cn(
                            'mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md ring-1',
                            badge
                              ? badge.chip
                              : 'bg-slate-100 text-slate-600 ring-slate-200',
                          )}
                        >
                          <BadgeIcon className="h-4 w-4" />
                        </span>
                        <span className="min-w-0">
                          <span className="flex items-center gap-2">
                            <span className="text-sm font-semibold text-slate-800">
                              {presetLabel(name, meta)}
                            </span>
                            {badge && (
                              <span
                                className={cn(
                                  'rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                                  badge.chip,
                                )}
                              >
                                {badge.label}
                              </span>
                            )}
                          </span>
                          {meta?.description && (
                            <span className="mt-0.5 block text-xs leading-snug text-slate-500">
                              {meta.description}
                            </span>
                          )}
                          {/* v4.2.2: estimated runtime derived from the
                              profile badge. */}
                          {eta && (
                            <span
                              className="mt-1 inline-flex items-center gap-1 text-[10px] text-slate-400"
                              title="Ballpark estimate derived from the profile's depth badge"
                            >
                              <Clock className="h-3 w-3" /> {eta}
                            </span>
                          )}
                          <span className="mt-1 block truncate font-mono text-[10px] text-slate-400">
                            {Object.entries(values)
                              .filter(([k]) => k !== 'target')
                              .map(([k, v]) => `${k}=${String(v)}`)
                              .join('  ') || 'default values'}
                          </span>
                        </span>
                      </button>
                    )
                  })}
                  {/* Custom: manual configuration, no preset applied. */}
                  <button
                    type="button"
                    onClick={() => applyPreset(null)}
                    className={cn(
                      'flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors',
                      preset === null
                        ? 'border-brand-500 bg-brand-50/70 ring-1 ring-brand-500'
                        : 'border-dashed border-slate-300 bg-white hover:border-slate-400 hover:bg-slate-50',
                    )}
                  >
                    <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-slate-100 text-slate-600 ring-1 ring-slate-200">
                      <SlidersHorizontal className="h-4 w-4" />
                    </span>
                    <span className="min-w-0">
                      <span className="text-sm font-semibold text-slate-800">Custom</span>
                      <span className="mt-0.5 block text-xs leading-snug text-slate-500">
                        Configure every option manually below.
                      </span>
                    </span>
                  </button>
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

