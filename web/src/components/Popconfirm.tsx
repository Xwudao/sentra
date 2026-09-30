import { useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

import { Button } from './ui'
import s from './popconfirm.module.scss'

type PopconfirmProps = {
  children: ReactNode
  title: string
  message?: string
  onConfirm: () => void
  confirmText?: string
  confirmDanger?: boolean
}

export function Popconfirm({ children, title, message, onConfirm, confirmText = 'Delete', confirmDanger = true }: PopconfirmProps) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState({ top: 0, left: 0 })
  const triggerRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const id = useId()

  useLayoutEffect(() => {
    if (!open) return

    function updatePosition() {
      const trigger = triggerRef.current?.getBoundingClientRect()
      const panel = panelRef.current
      if (!trigger || !panel) return
      const gap = 6
      const margin = 12
      const left = Math.max(margin, Math.min(trigger.right - panel.offsetWidth, window.innerWidth - panel.offsetWidth - margin))
      const below = trigger.bottom + gap
      const top = below + panel.offsetHeight <= window.innerHeight - margin
        ? below
        : Math.max(margin, trigger.top - panel.offsetHeight - gap)
      setPosition({ top, left })
    }

    updatePosition()
    panelRef.current?.querySelector('button')?.focus()
    const onPointerDown = (event: PointerEvent) => {
      if (!triggerRef.current?.contains(event.target as Node) && !panelRef.current?.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        setOpen(false)
        triggerRef.current?.querySelector('button')?.focus()
      }
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown, true)
    window.addEventListener('resize', updatePosition)
    window.addEventListener('scroll', updatePosition, true)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown, true)
      window.removeEventListener('resize', updatePosition)
      window.removeEventListener('scroll', updatePosition, true)
    }
  }, [open])

  return (
    <div className={s.trigger} ref={triggerRef} onClick={(event) => event.stopPropagation()}>
      <div aria-haspopup="dialog" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen((value) => !value)}>
        {children}
      </div>
      {open && createPortal(
        <div id={id} ref={panelRef} className={s.panel} style={position} role="dialog" aria-label={title}>
          <div className={s.title}>{title}</div>
          {message && <div className={s.message}>{message}</div>}
          <div className={s.actions}>
            <Button size="sm" type="button" onClick={() => { setOpen(false); triggerRef.current?.querySelector('button')?.focus() }}>Cancel</Button>
            <Button size="sm" type="button" variant={confirmDanger ? 'danger' : 'primary'} onClick={() => { setOpen(false); onConfirm() }}>{confirmText}</Button>
          </div>
        </div>,
        document.body,
      )}
    </div>
  )
}
