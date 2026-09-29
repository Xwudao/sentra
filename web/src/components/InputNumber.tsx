import { forwardRef, useEffect, useRef, useState, type ChangeEvent, type CSSProperties, type FocusEvent, type KeyboardEvent, type Ref } from 'react'

import { cx } from './cx'
import s from './input-number.module.scss'

export interface InputNumberProps {
  className?: string
  value?: number | null
  onChange?: (value: number | undefined) => void
  placeholder?: string
  min?: number
  max?: number
  step?: number
  disabled?: boolean
  name?: string
  id?: string
  autoComplete?: string
  autoFocus?: boolean
  readOnly?: boolean
  required?: boolean
  style?: CSSProperties
  onBlur?: (e: FocusEvent<HTMLInputElement>) => void
  onFocus?: (e: FocusEvent<HTMLInputElement>) => void
  onKeyDown?: (e: KeyboardEvent<HTMLInputElement>) => void
  onKeyUp?: (e: KeyboardEvent<HTMLInputElement>) => void
}

function clampValue(value: number, min?: number, max?: number) {
  let next = value
  if (min !== undefined) next = Math.max(min, next)
  if (max !== undefined) next = Math.min(max, next)
  return next
}

function toDisplayValue(value?: number | null) {
  return value === null || value === undefined ? '' : String(value)
}

function assignRef(ref: Ref<HTMLInputElement> | undefined, node: HTMLInputElement | null) {
  if (!ref) return
  if (typeof ref === 'function') ref(node)
  else ref.current = node
}

export const InputNumber = forwardRef<HTMLInputElement, InputNumberProps>(function InputNumber(
  {
    className,
    value,
    onChange,
    placeholder,
    min,
    max,
    step = 1,
    disabled,
    name,
    id,
    autoComplete,
    autoFocus,
    readOnly,
    required,
    style,
    onBlur,
    onFocus,
    onKeyDown,
    onKeyUp,
  },
  ref,
) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [displayValue, setDisplayValue] = useState(() => toDisplayValue(value))
  const [focused, setFocused] = useState(false)

  useEffect(() => {
    if (focused) return
    setDisplayValue(toDisplayValue(value))
  }, [focused, value])

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const raw = event.target.value
    if (raw === '') {
      setDisplayValue('')
      onChange?.(undefined)
      return
    }
    if (!/^-?\d*(\.\d*)?$/.test(raw)) return
    setDisplayValue(raw)
    const next = Number(raw)
    if (!Number.isNaN(next)) onChange?.(next)
  }

  function commit() {
    if (displayValue === '') return
    const parsed = Number(displayValue)
    if (Number.isNaN(parsed)) {
      setDisplayValue(toDisplayValue(value))
      return
    }
    const next = clampValue(parsed, min, max)
    setDisplayValue(String(next))
    onChange?.(next)
  }

  function stepBy(direction: 1 | -1) {
    if (disabled || readOnly) return
    const base = displayValue === '' || Number.isNaN(Number(displayValue)) ? (value ?? min ?? 0) : Number(displayValue)
    const next = clampValue(base + direction * step, min, max)
    setDisplayValue(String(next))
    onChange?.(next)
    inputRef.current?.focus()
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowUp') {
      event.preventDefault()
      stepBy(1)
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      stepBy(-1)
    }
    onKeyDown?.(event)
  }

  const numeric = displayValue === '' || Number.isNaN(Number(displayValue)) ? value : Number(displayValue)
  const canIncrease = !disabled && !readOnly && (max === undefined || (numeric ?? 0) < max)
  const canDecrease = !disabled && !readOnly && (min === undefined || (numeric ?? 0) > min)

  return (
    <div className={cx(s.wrapper, disabled && s.disabled, className)} style={style}>
      <input
        ref={(node) => {
          inputRef.current = node
          assignRef(ref, node)
        }}
        id={id}
        name={name}
        type="text"
        inputMode="decimal"
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        required={required}
        readOnly={readOnly}
        disabled={disabled}
        placeholder={placeholder}
        value={displayValue}
        className={s.input}
        onChange={handleChange}
        onBlur={(event) => {
          commit()
          setFocused(false)
          onBlur?.(event)
        }}
        onFocus={(event) => {
          setFocused(true)
          onFocus?.(event)
        }}
        onKeyDown={handleKeyDown}
        onKeyUp={onKeyUp}
      />
      <div className={s.actions}>
        <button
          type="button"
          className={s.actionButton}
          onClick={() => stepBy(1)}
          disabled={!canIncrease}
          tabIndex={-1}
          aria-label="Increase"
        >
          <span className="i-lucide-plus" aria-hidden="true" />
        </button>
        <button
          type="button"
          className={s.actionButton}
          onClick={() => stepBy(-1)}
          disabled={!canDecrease}
          tabIndex={-1}
          aria-label="Decrease"
        >
          <span className="i-lucide-minus" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
})

InputNumber.displayName = 'InputNumber'
