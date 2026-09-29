import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'

import { cx } from './cx'
import s from './select.module.scss'

export interface SelectOption {
  value: string
  label: ReactNode
  disabled?: boolean
}

export interface SelectProps {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  placeholder?: string
  disabled?: boolean
  className?: string
  id?: string
  'aria-label'?: string
  size?: 'md' | 'sm'
}

const GAP = 6
const MAX_HEIGHT = 264
const VIEWPORT_PADDING = 8

export function Select({
  value,
  onChange,
  options,
  placeholder = 'Select an option',
  disabled,
  className,
  id,
  'aria-label': ariaLabel,
  size = 'md',
}: SelectProps) {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const [menuStyle, setMenuStyle] = useState<CSSProperties>()
  const wrapperRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const listboxId = useId()
  const selected = options.find((option) => option.value === value)

  // Options/value are often passed as fresh objects/arrays on every render.
  // Keep them in refs so the open-positioning effect only runs when the menu
  // actually opens, instead of resetting keyboard navigation on each render.
  const optionsRef = useRef(options)
  optionsRef.current = options
  const valueRef = useRef(value)
  valueRef.current = value

  const close = useCallback(() => {
    setOpen(false)
  }, [])

  const reposition = useCallback(() => {
    const trigger = triggerRef.current
    if (!trigger) return
    const rect = trigger.getBoundingClientRect()
    const viewportHeight = window.innerHeight
    const spaceBelow = viewportHeight - rect.bottom - GAP - VIEWPORT_PADDING
    const spaceAbove = rect.top - GAP - VIEWPORT_PADDING
    const idealHeight = optionsRef.current.length * 38 + 12
    const openUp = spaceBelow < Math.min(MAX_HEIGHT, idealHeight) && spaceAbove > spaceBelow

    const style: CSSProperties = {
      left: rect.left,
      width: rect.width,
      maxHeight: Math.max(64, Math.min(openUp ? spaceAbove : spaceBelow, MAX_HEIGHT)),
    }
    if (openUp) {
      style.bottom = viewportHeight - rect.top + GAP
    } else {
      style.top = rect.bottom + GAP
    }
    setMenuStyle(style)
  }, [])

  useLayoutEffect(() => {
    if (!open) return
    reposition()
    const index = optionsRef.current.findIndex((option) => option.value === valueRef.current)
    setActiveIndex(index >= 0 ? index : 0)
    const frame = window.requestAnimationFrame(() => menuRef.current?.focus())
    return () => window.cancelAnimationFrame(frame)
  }, [open, reposition])

  useEffect(() => {
    if (!open) return
    window.addEventListener('resize', reposition)
    window.addEventListener('scroll', reposition, true)
    return () => {
      window.removeEventListener('resize', reposition)
      window.removeEventListener('scroll', reposition, true)
    }
  }, [open, reposition])

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node
      if (wrapperRef.current?.contains(target)) return
      if (menuRef.current?.contains(target)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open])

  useEffect(() => {
    if (!open) return
    const item = menuRef.current?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)
    item?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex, open])

  function move(delta: number) {
    if (options.length === 0) return
    setActiveIndex((current) => {
      let next = current
      for (let step = 0; step < options.length; step += 1) {
        next = (next + delta + options.length) % options.length
        if (!options[next]?.disabled) return next
      }
      return current
    })
  }

  function commit(index: number) {
    const option = options[index]
    if (!option || option.disabled) return
    onChange(option.value)
    setOpen(false)
    triggerRef.current?.focus()
  }

  function onTriggerKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (disabled) return
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp':
        event.preventDefault()
        setOpen(true)
        break
      case 'Enter':
      case ' ':
        event.preventDefault()
        setOpen((current) => !current)
        break
      case 'Escape':
        if (open) {
          event.preventDefault()
          close()
        }
        break
      default:
        break
    }
  }

  function onMenuKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        move(1)
        break
      case 'ArrowUp':
        event.preventDefault()
        move(-1)
        break
      case 'Home':
        event.preventDefault()
        setActiveIndex(0)
        break
      case 'End':
        event.preventDefault()
        setActiveIndex(options.length - 1)
        break
      case 'Enter':
      case ' ':
        event.preventDefault()
        commit(activeIndex)
        break
      case 'Escape':
        event.preventDefault()
        close()
        triggerRef.current?.focus()
        break
      case 'Tab':
        setOpen(false)
        break
      default:
        break
    }
  }

  return (
    <div ref={wrapperRef} className={cx(s.wrapper, className)}>
      <button
        ref={triggerRef}
        type="button"
        id={id}
        className={cx(s.trigger, size === 'sm' && s.sm, open && s.triggerOpen, disabled && s.triggerDisabled)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => setOpen((current) => !current)}
        onKeyDown={onTriggerKeyDown}
      >
        <span className={cx(s.triggerLabel, !selected && s.placeholder)}>{selected ? selected.label : placeholder}</span>
        <span className={cx('i-lucide-chevron-down', s.chevron, open && s.chevronOpen)} aria-hidden="true" />
      </button>

      {open
        ? createPortal(
            <div
              ref={menuRef}
              id={listboxId}
              role="listbox"
              tabIndex={-1}
              className={s.menu}
              style={menuStyle}
              onKeyDown={onMenuKeyDown}
              aria-activedescendant={options[activeIndex] ? `${listboxId}-${activeIndex}` : undefined}
            >
              {options.length === 0 ? (
                <div className={s.empty}>No options available</div>
              ) : (
                options.map((option, index) => {
                  const isSelected = option.value === value
                  return (
                    <button
                      key={option.value}
                      id={`${listboxId}-${index}`}
                      data-index={index}
                      type="button"
                      role="option"
                      aria-selected={isSelected}
                      disabled={option.disabled}
                      className={cx(s.option, index === activeIndex && s.optionActive, option.disabled && s.optionDisabled)}
                      onMouseEnter={() => setActiveIndex(index)}
                      onClick={() => commit(index)}
                    >
                      <span className={s.optionLabel}>{option.label}</span>
                      {isSelected ? <span className={cx('i-lucide-check', s.optionCheck)} aria-hidden="true" /> : null}
                    </button>
                  )
                })
              )}
            </div>,
            document.body,
          )
        : null}
    </div>
  )
}
