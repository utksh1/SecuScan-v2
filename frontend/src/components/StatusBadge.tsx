import { cn, STATUS_CLASSES } from '@/utils/format'
import { Loader2 } from 'lucide-react'

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn('chip capitalize', STATUS_CLASSES[status] ?? STATUS_CLASSES.queued)}>
      {status === 'running' && <Loader2 className="h-3 w-3 animate-spin" />}
      {status}
    </span>
  )
}
