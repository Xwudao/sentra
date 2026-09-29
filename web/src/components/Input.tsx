import { forwardRef, useRef, useState, type InputHTMLAttributes, type Ref } from 'react'

import { cx } from './cx'
import s from './input.module.scss'

type InputType = 'text' | 'password' | 'email' | 'url' | 'tel' | 'search' | 'number'

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  type?: InputType
  /** Show a clear button when the field has a value. */
  showClear?: boolean
  /** Optional leading UnoCSS icon class, e.g. `i-lucide-search`. */
  leadingIcon?: string
}

function assignRef(ref: Ref<HTMLInputElement> | undefined, node: HTMLInputElement | null) {
  if (!ref) return
  if (typeof ref === 'function') ref(node)
  else ref.current = node
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { className, type = 'text', showClear, leadingIcon, disabled, value, ...rest },
  ref,
) {
  const innerRef = useRef<HTMLInputElement>(null)
  const [visible, setVisible] = useState(false)

  const isPassword = type === 'password'
  const hasValue = value !== undefined && value !== null && String(value) !== ''
  const showClearButton = showClear && hasValue && !disabled
  const actualType = isPassword ? (visible ? 'text' : 'password') : type
  const hasTrailing = showClearButton || isPassword

  function clear() {
    const input = innerRef.current
    if (!input) return
    // Update through the native setter so React's onChange sees the change.
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set
    setter?.call(input, '')
    input.dispatchEvent(new Event('input', { bubbles: true }))
    input.focus()
  }

  return (
    <span className={cx(s.wrapper, disabled && s.disabled, className)}>
      {leadingIcon ? <span className={cx(leadingIcon, s.leadingIcon)} aria-hidden="true" /> : null}
      <input
        ref={(node) => {
          innerRef.current = node
          assignRef(ref, node)
        }}
        type={actualType}
        className={cx(s.input, leadingIcon && s.hasLeading, hasTrailing && s.hasTrailing)}
        disabled={disabled}
        value={value}
        {...rest}
      />
      {hasTrailing ? (
        <span className={s.trailing}>
          {showClearButton ? (
            <button type="button" className={s.iconBtn} onClick={clear} tabIndex={-1} aria-label="Clear">
              <span className="i-lucide-x" aria-hidden="true" />
            </button>
          ) : null}
          {isPassword ? (
            <button
              type="button"
              className={s.iconBtn}
              onClick={() => setVisible((v) => !v)}
              tabIndex={-1}
              aria-label={visible ? 'Hide password' : 'Show password'}
            >
              <span className={visible ? 'i-lucide-eye-off' : 'i-lucide-eye'} aria-hidden="true" />
            </button>
          ) : null}
        </span>
      ) : null}
    </span>
  )
})

Input.displayName = 'Input'
