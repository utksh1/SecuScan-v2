import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Search, CirclePlus, Radar, SearchX } from 'lucide-react'
import { request } from '@/api/client'
import type { Plugin } from '@/api/types'
import { SafetyBadge } from '@/components/SafetyBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { cn } from '@/utils/format'

export function ScannersPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['plugins'],
    queryFn: () => request<{ items: Plugin[] }>('/plugins'),
  })
  const [category, setCategory] = useState<string>('all')
  const [search, setSearch] = useState('')

  const plugins = data?.items ?? []
  const categories = useMemo(() => {
    const set = new Map<string, number>()
    for (const p of plugins) set.set(p.category, (set.get(p.category) ?? 0) + 1)
    return [...set.entries()].sort()
  }, [plugins])

  const filtered = plugins.filter((p) => {
    if (category !== 'all' && p.category !== category) return false
    if (search && !`${p.name} ${p.id} ${p.tags.join(' ')}`.toLowerCase().includes(search.toLowerCase()))
      return false
    return true
  })

  if (isLoading) return <Spinner label="Loading scanner catalog…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="input pl-9"
            placeholder="Search scanners, tags…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search scanners"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <CategoryChip
            active={category === 'all'}
            onClick={() => setCategory('all')}
            label={`All ${plugins.length}`}
          />
          {categories.map(([cat, n]) => (
            <CategoryChip
              key={cat}
              active={category === cat}
              onClick={() => setCategory(cat)}
              label={`${cat} ${n}`}
            />
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={<SearchX className="h-8 w-8" />}
          title="No scanners match"
          description="Try a different search or category."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((p) => (
            <PluginCard key={p.id} plugin={p} />
          ))}
        </div>
      )}
    </div>
  )
}

function CategoryChip({
  active,
  onClick,
  label,
}: {
  active: boolean
  onClick: () => void
  label: string
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'chip capitalize transition-colors',
        active
          ? 'bg-brand-600 text-white'
          : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50',
      )}
    >
      {label}
    </button>
  )
}

function PluginCard({ plugin }: { plugin: Plugin }) {
  const startable = plugin.available && plugin.enabled
  return (
    <div
      className={cn(
        'card flex flex-col gap-3 p-5',
        !startable && 'opacity-80',
      )}
      data-testid={`plugin-${plugin.id}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
            <Radar className="h-5 w-5" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-slate-800">{plugin.name}</h3>
            <div className="text-xs text-slate-400">
              {plugin.id} · v{plugin.version}
              {plugin.engine.type === 'native' && (
                <span className="ml-1 rounded bg-emerald-50 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700">
                  native
                </span>
              )}
            </div>
          </div>
        </div>
        <SafetyBadge level={plugin.safety.level} />
      </div>

      <p className="line-clamp-2 text-sm text-slate-500">{plugin.description}</p>

      <div className="flex flex-wrap gap-1">
        <span className="chip bg-slate-100 text-slate-600">{plugin.category}</span>
        {plugin.difficulty && (
          <span className="chip bg-slate-100 capitalize text-slate-600">{plugin.difficulty}</span>
        )}
        {plugin.tags.slice(0, 3).map((t) => (
          <span key={t} className="chip bg-slate-50 text-slate-500">
            #{t}
          </span>
        ))}
      </div>

      {!plugin.available && (
        <div className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 ring-1 ring-amber-100">
          Missing binaries: <span className="font-mono">{plugin.missing_binaries.join(', ')}</span>
        </div>
      )}
      {!plugin.enabled && (
        <div className="rounded-lg bg-slate-100 px-3 py-2 text-xs text-slate-500">
          Disabled by administrator.
        </div>
      )}

      <div className="mt-auto flex items-center justify-between pt-1">
        <span className="text-xs text-slate-400">
          {plugin.safety.max_concurrent} parallel ·{' '}
          {plugin.safety.max_per_hour > 0 ? `${plugin.safety.max_per_hour}/hour` : 'unlimited'}
        </span>
        <Link
          to={`/tasks/new?plugin=${plugin.id}`}
          className={startable ? 'btn-primary text-xs' : 'btn-secondary text-xs'}
          aria-disabled={!startable}
        >
          <CirclePlus className="h-3.5 w-3.5" />
          {startable ? 'New task' : 'Unavailable'}
        </Link>
      </div>
    </div>
  )
}
