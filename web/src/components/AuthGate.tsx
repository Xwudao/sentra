import { useEffect, useState } from 'react'

import { api } from '@/lib/api'
import { useAuth } from '@/store/auth'
import { Button, Field, Input } from './ui'
import s from './auth-gate.module.scss'

export function AuthGate({ children }: { children: React.ReactNode }) {
  const token = useAuth((s) => s.token)
  const [state, setState] = useState<'checking' | 'ok' | 'auth'>('checking')

  useEffect(() => {
    let cancelled = false
    setState('checking')
    api
      .get('/api/dashboard')
      .then(() => !cancelled && setState('ok'))
      .catch((e: { status?: number }) => {
        if (cancelled) return
        setState(e.status === 401 ? 'auth' : 'ok')
      })
    return () => {
      cancelled = true
    }
  }, [token])

  if (state === 'checking') {
    return (
      <div className={s.center}>
        <span className={s.spinner} />
      </div>
    )
  }

  if (state === 'auth') {
    return <LoginScreen />
  }

  return <>{children}</>
}

function LoginScreen() {
  const setToken = useAuth((s) => s.setToken)
  const [value, setValue] = useState('')

  return (
    <div className={s.center}>
      <div className={s.loginCard}>
        <div className={s.brandRow}>
          <span className={s.brandMark}>
            <span className="i-lucide-shield-half" />
          </span>
          <h1 className={s.brandName}>Sentra WAF</h1>
        </div>
        <p className={s.lead}>Enter the admin token configured for this instance to access the management API.</p>
        <form
          className={s.form}
          onSubmit={(e) => {
            e.preventDefault()
            setToken(value.trim())
          }}
        >
          <Field label="Admin token">
            <Input
              type="password"
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Bearer token"
            />
          </Field>
          <Button variant="primary" type="submit">
            <span className="i-lucide-log-in" /> Sign in
          </Button>
        </form>
      </div>
    </div>
  )
}
