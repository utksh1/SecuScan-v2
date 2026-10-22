import { cn, SEVERITY_CLASSES } from '@/utils/format'

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={cn('chip uppercase tracking-wide', SEVERITY_CLASSES[severity] ?? SEVERITY_CLASSES.info)}
      data-testid={`severity-${severity}`}
    >
      {severity}
    </span>
  )
}
