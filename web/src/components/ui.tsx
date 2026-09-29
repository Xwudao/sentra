import type { ButtonHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react'
import { useEffect, useRef } from 'react'

import type { Action, Severity } from '@/lib/types'
import { cx } from './cx'
import s from './ui.module.scss'

export { cx } from './cx'
export { Input } from './Input'
export type { InputProps } from './Input'
export { InputNumber } from './InputNumber'
export type { InputNumberProps } from './InputNumber'
export { Select } from './Select'
export type { SelectOption, SelectProps } from './Select'

export function Card({ children, className, flush }: { children: ReactNode; className?: string; flush?: boolean }) {
  return <div className={cx(s.card, flush && s.cardFlush, className)}>{children}</div>
}

export function CardHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className={s.cardHeader}>
      <div className={s.cardHeaderText}>
        <div className={s.cardTitle}>{title}</div>
        {subtitle ? <div className={s.cardSubtitle}>{subtitle}</div> : null}
      </div>
      {actions ? <div className={s.cardActions}>{actions}</div> : null}
    </div>
  )
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className={s.pageHeader}>
      <div className={s.pageHeaderText}>
        <h1 className={s.pageTitle}>{title}</h1>
        {description ? <p className={s.pageDescription}>{description}</p> : null}
      </div>
      {actions ? <div className={s.pageActions}>{actions}</div> : null}
    </div>
  )
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  size?: 'md' | 'sm' | 'lg'
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
        size === 'lg' && s.lg,
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}

export function IconButton({ size = 'md', className, children, ...rest }: ButtonProps) {
  return (
    <button className={cx(s.btn, s.ghost, s.iconBtn, size === 'sm' && s.sm, className)} {...rest}>
      {children}
    </button>
  )
}

export function Badge({ children, tone }: { children: ReactNode; tone?: 'block' | 'allow' | 'log' | 'default' }) {
  return (
    <span className={cx(s.badge, tone === 'block' && s.block, tone === 'allow' && s.allow, tone === 'log' && s.log)}>
      <span className={s.badgeDot} aria-hidden="true" />
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
    <div className={s.loadingOverlay} role="status">
      <span className={s.spinner} />
      {label ? <span>{label}</span> : null}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  children,
}: {
  icon?: string
  title?: ReactNode
  description?: ReactNode
  action?: ReactNode
  children?: ReactNode
}) {
  if (!title && children) {
    return <div className={s.empty}>{children}</div>
  }
  return (
    <div className={s.empty}>
      {icon ? <div className={s.emptyIllustration}>{<span className={icon} aria-hidden="true" />}</div> : null}
      <div className={s.emptyContent}>
        {title ? <div className={s.emptyTitle}>{title}</div> : null}
        {description ? <div className={s.emptyDescription}>{description}</div> : null}
      </div>
      {action ? <div className={s.emptyAction}>{action}</div> : null}
    </div>
  )
}

export function TableShell({ children }: { children: ReactNode }) {
  return (
    <div className={s.tableWrap}>
      <table className={s.table}>{children}</table>
    </div>
  )
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', onKey)
    const frame = window.requestAnimationFrame(() => panelRef.current?.focus())
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = previousOverflow
      window.cancelAnimationFrame(frame)
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div className={s.modalBackdrop} onMouseDown={onClose}>
      <div
        ref={panelRef}
        className={s.modal}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className={s.modalHeader}>
          <div className={s.cardTitle}>{title}</div>
          <IconButton onClick={onClose} aria-label="Close">
            <span className="i-lucide-x" />
          </IconButton>
        </div>
        <div className={s.modalBody}>{children}</div>
      </div>
    </div>
  )
}

export function StatCard({
  label,
  value,
  tone,
  icon,
  hint,
}: {
  label: string
  value: ReactNode
  tone?: 'danger' | 'success' | 'accent'
  icon?: string
  hint?: string
}) {
  const valueTone = tone === 'danger' ? s.toneDanger : tone === 'success' ? s.toneSuccess : tone === 'accent' ? s.toneAccent : undefined
  const iconTone =
    tone === 'danger' ? s.toneDangerIcon : tone === 'success' ? s.toneSuccessIcon : tone === 'accent' ? s.toneAccentIcon : undefined
  return (
    <Card className={s.statCard}>
      <div className={s.statHead}>
        <span className={s.statLabel}>{label}</span>
        {icon ? <span className={cx(s.statIcon, iconTone)}>{<span className={icon} aria-hidden="true" />}</span> : null}
      </div>
      <div className={cx(s.statValue, valueTone)}>{value}</div>
      {hint ? <div className={s.statHint}>{hint}</div> : null}
    </Card>
  )
}

export function Chip({ children }: { children: ReactNode }) {
  return <span className={s.chip}>{children}</span>
}

export function Pagination({
  offset,
  pageSize,
  total,
  onChange,
}: {
  offset: number
  pageSize: number
  total: number
  onChange: (next: number) => void
}) {
  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + pageSize, total)
  const hasPrev = offset > 0
  const hasNext = offset + pageSize < total
  return (
    <div className={s.pagination}>
      <span className={s.pageInfo}>
        {from}–{to} of {total}
      </span>
      <div className={s.pageButtons}>
        <Button size="sm" disabled={!hasPrev} onClick={() => onChange(Math.max(0, offset - pageSize))}>
          <span className="i-lucide-chevron-left" /> Prev
        </Button>
        <Button size="sm" disabled={!hasNext} onClick={() => onChange(offset + pageSize)}>
          Next <span className="i-lucide-chevron-right" />
        </Button>
      </div>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className={s.tabs} role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={value === t.id}
          className={cx(s.tab, value === t.id && s.tabActive)}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}
