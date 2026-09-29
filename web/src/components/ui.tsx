import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import { useEffect } from 'react'

import type { Action, Severity } from '@/lib/types'
import s from './ui.module.scss'

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx(s.card, className)}>{children}</div>
}

export function CardHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className={s.cardHeader}>
      <div>
        <div className={s.cardTitle}>{title}</div>
        {subtitle ? <div className={s.cardSubtitle}>{subtitle}</div> : null}
      </div>
      {actions}
    </div>
  )
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className={s.pageHeader}>
      <div>
        <h1 className={s.pageTitle}>{title}</h1>
        {description ? <p className={s.pageDescription}>{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  )
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  size?: 'md' | 'sm'
}

export function Button({ variant = 'default', size = 'md', className, children, ...rest }: ButtonProps) {
  return (
    <button
      className={cx(
        s.btn,
        variant === 'primary' && s.primary,
        variant === 'danger' && s.danger,
        variant === 'ghost' && s.ghost,
        size === 'sm' && s.sm,
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}

export function IconButton({ className, children, ...rest }: ButtonProps) {
  return (
    <button className={cx(s.btn, s.ghost, s.iconBtn, className)} {...rest}>
      {children}
    </button>
  )
}

export function Badge({ children, tone }: { children: ReactNode; tone?: 'block' | 'allow' | 'log' | 'default' }) {
  return (
    <span className={cx(s.badge, tone === 'block' && s.block, tone === 'allow' && s.allow, tone === 'log' && s.log)}>
      {children}
    </span>
  )
}

export function ActionBadge({ action }: { action: Action | string }) {
  const tone = action === 'block' ? 'block' : action === 'allow' ? 'allow' : 'log'
  return <Badge tone={tone}>{action}</Badge>
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const cls =
    severity === 'critical'
      ? s.sevCritical
      : severity === 'high'
        ? s.sevHigh
        : severity === 'medium'
          ? s.sevMedium
          : s.sevLow
  return <span className={cx(s.badge, cls)}>{severity}</span>
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className={s.field}>
      <span className={s.label}>{label}</span>
      {children}
      {hint ? <span className={s.hint}>{hint}</span> : null}
    </label>
  )
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(s.input, className)} {...rest} />
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cx(s.select, className)} {...rest}>
      {children}
    </select>
  )
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(s.textarea, className)} {...rest} />
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={cx(s.toggle, checked && s.toggleOn)}
      onClick={() => onChange(!checked)}
    >
      <span className={s.toggleKnob} />
    </button>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className={s.loadingOverlay}>
      <span className={s.spinner} />
      {label ? <span>{label}</span> : null}
    </div>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className={s.empty}>{children}</div>
}

export function TableShell({ children }: { children: ReactNode }) {
  return (
    <div className={s.tableWrap}>
      <table className={s.table}>{children}</table>
    </div>
  )
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null
  return (
    <div className={s.modalBackdrop} onClick={onClose}>
      <div className={s.modal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className={s.cardHeader}>
          <div className={s.cardTitle}>{title}</div>
          <IconButton onClick={onClose} aria-label="Close">
            <span className="i-lucide-x" />
          </IconButton>
        </div>
        {children}
      </div>
    </div>
  )
}

export function StatCard({ label, value, tone }: { label: string; value: ReactNode; tone?: 'danger' | 'success' | 'accent' }) {
  const color = tone === 'danger' ? 'var(--danger)' : tone === 'success' ? 'var(--success)' : tone === 'accent' ? 'var(--accent)' : undefined
  return (
    <Card>
      <div className={s.statLabel}>{label}</div>
      <div className={s.statValue} style={color ? { color } : undefined}>
        {value}
      </div>
    </Card>
  )
}

export function Chip({ children }: { children: ReactNode }) {
  return <span className={s.chip}>{children}</span>
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className={s.tabs}>
      {tabs.map((t) => (
        <button key={t.id} type="button" className={cx(s.tab, value === t.id && s.tabActive)} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  )
}
