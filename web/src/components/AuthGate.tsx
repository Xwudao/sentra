import { useEffect, useState } from 'react'

import { api } from '@/lib/api'
import { useAuth } from '@/store/auth'
import { Button, Card, Field, Input } from './ui'

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
      <div className="min-h-100dvh grid place-items-center">
        <span className="w-8 h-8 rounded-full border-2 border-[var(--border-strong)] border-t-[var(--accent)] animate-spin" />
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
    <div className="min-h-100dvh grid place-items-center p-6">
      <Card className="w-full max-w-sm">
        <div className="flex items-center gap-2 mb-4">
          <span className="grid place-items-center w-8 h-8 rounded-md bg-[var(--accent)] text-white">
            <span className="i-lucide-shield-half" />
          </span>
          <h1 className="text-lg font-semibold">Sentra WAF</h1>
        </div>
        <p className="text-sm text-[var(--text-muted)] mb-4">
          Enter the admin token configured for this instance to access the management API.
        </p>
        <form
          className="flex flex-col gap-4"
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
      </Card>
    </div>
  )
}
