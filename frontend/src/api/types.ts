// Shared domain types mirroring the Rust API payloads.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingKind = 'observation' | 'suspected_issue' | 'validated_issue'
export type AnalystStatus =
  | 'new'
  | 'confirmed'
  | 'needs_review'
  | 'false_positive'
  | 'accepted_risk'
  | 'fixed'
export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type SafetyLevel = 'safe' | 'intrusive' | 'exploit'
export type Role = 'admin' | 'scanner' | 'viewer'

export interface User {
  id: string
  email: string
  name: string
  role: Role
  created_at: string
}

export interface FieldOption {
  value: string
  label: string
}

export interface PluginField {
  id: string
  label: string
  type: 'string' | 'text' | 'integer' | 'boolean' | 'select'
  required: boolean
  default?: unknown
  placeholder?: string
  help?: string
  pattern?: string
  message?: string
  options?: FieldOption[]
  min?: number
  max?: number
}

export interface Plugin {
  id: string
  name: string
  version: string
  description: string
  long_description?: string
  category: string
  icon?: string
  difficulty?: string
  tags: string[]
  engine: {
    type: 'cli' | 'native'
    binary?: string
    native?: string
    timeout_seconds: number
  }
  fields: PluginField[]
  presets: Record<string, Record<string, unknown>>
  safety: {
    level: SafetyLevel
    requires_consent: boolean
    consent_message?: string
    allowed_targets: string[]
    max_concurrent: number
    max_per_hour: number
    capabilities: string[]
  }
  dependencies: { binaries: string[] }
  available: boolean
  missing_binaries: string[]
  enabled: boolean
}

export interface Task {
  id: string
  user_id: string
  plugin_id: string
  plugin_name: string
  target?: string
  status: TaskStatus
  inputs: Record<string, unknown>
  options: Record<string, unknown>
  exit_code?: number
  error?: string
  stats?: {
    findings?: number
    duration_ms?: number
    tool_exit_nonzero?: boolean
  }
  output_truncated: boolean
  workflow_run_id?: string
  workspace_id?: string
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface Finding {
  id: string
  task_id: string
  plugin_id: string
  severity: Severity
  kind: FindingKind
  analyst_status: AnalystStatus
  category: string
  title: string
  description: string
  remediation: string
  proof: string
  url?: string
  metadata: Record<string, unknown>
  created_at: string
}

export interface DashboardSummary {
  tasks: {
    total: number
    running: number
    queued: number
    completed: number
    failed: number
    cancelled: number
  }
  findings: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    new: number
  }
  plugins: { total: number; available: number; enabled: number; load_issues: number }
  users_total: number
  workflows_total: number
  recent_tasks: Task[]
}

export interface WorkflowStep {
  plugin_id: string
  inputs: Record<string, unknown>
  preset?: string
  label?: string
}

export interface Workflow {
  id: string
  name: string
  description: string
  steps: WorkflowStep[]
  created_by: string
  created_at: string
  updated_at?: string
}

export interface WorkflowRun {
  id: string
  workflow_id: string
  status: TaskStatus
  task_ids: string[]
  error?: string
  created_at: string
  finished_at?: string
}

export interface ApiKey {
  id: string
  name: string
  prefix: string
  created_at: string
  last_used_at?: string
  revoked_at?: string
}

export interface AuditEntry {
  id: number
  ts: string
  user_id?: string
  plugin_id: string
  target: string
  verdict: string
  layer: string
  pattern: string
  reason: string
}

export interface Workspace {
  id: string
  name: string
  description: string
  created_by: string
  created_at: string
  updated_at?: string
  tasks_total: number
  tasks_active: number
  targets_total: number
}

export interface PersonalWorkspace {
  id: null
  name: 'Personal'
  tasks_total: number
  tasks_active: number
}

export interface WorkspaceList {
  items: Workspace[]
  personal: PersonalWorkspace
}

export type TargetKind = 'hostname' | 'ip_address' | 'url'

export interface ScanTarget {
  id: string
  workspace_id: string
  name: string
  kind: TargetKind
  description: string
  created_by: string
  created_at: string
  scans_total: number
  last_scanned_at?: string
}

export interface ApiErrorShape {
  error: { code: number; message: string }
}

export type ReportFormat =
  | 'md'
  | 'csv'
  | 'html'
  | 'sarif'
  | 'json'
  | 'pdf'
  | 'docx'
  | 'xlsx'

export type ReportJobStatus = 'waiting' | 'in_progress' | 'finished' | 'failed'

export interface ReportJob {
  id: string
  task_id: string
  format: ReportFormat
  severity_filter: string | null
  status: ReportJobStatus
  error: string | null
  file_bytes: number | null
  webhook_url: string | null
  webhook_attempts: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  download_path: string | null
}

export interface ReportJobList {
  items: ReportJob[]
  total: number
  limit: number
  offset: number
}
