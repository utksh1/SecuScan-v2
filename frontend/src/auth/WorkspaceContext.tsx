// Workspace scope: a lightweight context holding the currently selected
// workspace ("personal" = the synthetic no-workspace scope) plus the list
// query shared by the sidebar switcher and pages.
//
// The selection persists in localStorage so a reload keeps the scope.

import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { workspaceApi } from '@/api/client'
import type { Workspace } from '@/api/types'

const STORAGE_KEY = 'secuscan:workspace'

export type WorkspaceSelection = 'personal' | { id: string }

interface WorkspaceState {
  /** Currently selected workspace (null = Personal). */
  current: Workspace | null
  /** All workspaces (empty while loading). */
  workspaces: Workspace[]
  /** Selection value for the switcher: 'personal' | workspace id. */
  selected: string
  select: (id: string) => void
  /** Query-string value for backend scoping: 'none' | workspace id. */
  scopeParam: string
  isLoading: boolean
}

const WorkspaceContext = createContext<WorkspaceState | null>(null)

function readStoredId(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY)
  } catch {
    return null
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  // Initialize lazily from storage; '' / 'personal' both mean Personal.
  const [selected, setSelected] = useState<string>(() => {
    const stored = readStoredId()
    return stored && stored !== 'personal' ? stored : 'personal'
  })

  const { data, isLoading } = useQuery({
    queryKey: ['workspaces'],
    queryFn: () => workspaceApi.list(),
    // Keep the switcher counts fresh without hammering the API.
    refetchInterval: 15_000,
  })

  // If the selected workspace was deleted server-side, fall back to
  // Personal instead of pointing every query at a 404.
  const workspaces = data?.items ?? []
  const stillExists = selected === 'personal' || workspaces.some((w) => w.id === selected)
  useEffect(() => {
    if (!isLoading && !stillExists && selected !== 'personal') {
      setSelected('personal')
    }
  }, [isLoading, stillExists, selected])

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, selected)
    } catch {
      /* private mode: selection just won't persist */
    }
  }, [selected])

  const select = useCallback((id: string) => setSelected(id), [])

  const current = selected === 'personal' ? null : (workspaces.find((w) => w.id === selected) ?? null)

  return (
    <WorkspaceContext.Provider
      value={{
        current,
        workspaces,
        selected,
        select,
        scopeParam: selected === 'personal' ? 'none' : selected,
        isLoading,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  )
}

export function useWorkspace(): WorkspaceState {
  const ctx = useContext(WorkspaceContext)
  if (!ctx) throw new Error('useWorkspace must be used inside <WorkspaceProvider>')
  return ctx
}
