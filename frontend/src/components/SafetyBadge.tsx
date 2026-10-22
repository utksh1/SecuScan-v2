import { cn, SAFETY_CLASSES } from '@/utils/format'
import { ShieldAlert, ShieldCheck, Skull } from 'lucide-react'
import type { SafetyLevel } from '@/api/types'

const ICONS: Record<SafetyLevel, typeof ShieldCheck> = {
  safe: ShieldCheck,
  intrusive: ShieldAlert,
  exploit: Skull,
}

export function SafetyBadge({ level }: { level: SafetyLevel }) {
  const Icon = ICONS[level] ?? ShieldCheck
  return (
    <span className={cn('chip capitalize', SAFETY_CLASSES[level] ?? SAFETY_CLASSES.safe)}>
      <Icon className="h-3 w-3" />
      {level}
    </span>
  )
}
