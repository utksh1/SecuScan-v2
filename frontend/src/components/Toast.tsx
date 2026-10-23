// Minimal toast system (v3.1.3): fixed bottom-right stack with optional
// SPA links, auto-dismiss, manual close. Mounted once in App so toasts
// survive route navigation (e.g. "attack launched" survives the jump to
// /tasks).

import { createContext, useCallback, useContext, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'
import { cn } from '@/utils/format'

export interface ToastLink {
  label: string
  to: string
}

export interface Toast {
  title: string
  description?: string
  links?: ToastLink[]
  /** Auto-dismiss delay in ms (default 10000). */
  ttl?: number
}

interface ToastItem extends Toast {
  id: number
}

interface ToastApi {
  push: (t: Toast) => void
}

const ToastCtx = createContext<ToastApi>({ push: () => {} })

export function useToast(): ToastApi {
  return useContext(ToastCtx)
}

const DEFAULT_TTL = 10_000

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const nextId = useRef(1)

  const remove = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (t: Toast) => {
      const id = nextId.current++
      setItems((list) => [...list.slice(-4), { ...t, id }])
      window.setTimeout(() => remove(id), t.ttl ?? DEFAULT_TTL)
    },
    [remove],
  )

  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2"
      >
        {items.map((t) => (
          <div
            key={t.id}
            role="status"
            className="pointer-events-auto rounded-xl border border-slate-200 bg-white p-4 shadow-lg shadow-slate-900/10"
          >
            <div className="flex items-start gap-2">
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-slate-800">{t.title}</div>
                {t.description && (
                  <div className="mt-0.5 text-xs text-slate-500">{t.description}</div>
                )}
                {t.links && t.links.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {t.links.slice(0, 6).map((l) => (
                      <Link
                        key={l.to}
                        to={l.to}
                        onClick={() => remove(t.id)}
                        className="rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] font-medium text-brand-700 ring-1 ring-slate-200 transition-colors hover:bg-brand-50 hover:text-brand-800"
                      >
                        {l.label}
                      </Link>
                    ))}
                    {t.links.length > 6 && (
                      <span className="self-center text-[11px] text-slate-400">
                        +{t.links.length - 6} more
                      </span>
                    )}
                  </div>
                )}
              </div>
              <button
                type="button"
                aria-label="Dismiss"
                className={cn(
                  'shrink-0 rounded-md p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600',
                )}
                onClick={() => remove(t.id)}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}
