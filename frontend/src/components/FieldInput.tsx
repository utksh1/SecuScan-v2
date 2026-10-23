// Typed plugin-field control shared by the task launcher and the schedule
// editor (rendered from each plugin's declarative manifest).

import type { PluginField } from '@/api/types'

export function FieldInput({
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
