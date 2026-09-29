import { useEffect, useState } from 'react'

import { Button, Card, CardHeader, EmptyState, Field, IconButton, Input, PageHeader, Spinner } from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import type { RateLimitRule, Settings } from '@/lib/types'

export function RateLimitPage() {
  const { data, loading, reload } = useApiQuery<Settings>('/api/settings')
  const [settings, setSettings] = useState<Settings | null>(null)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (data) setSettings(data)
  }, [data])

  if (loading && !settings) return <Spinner label="Loading rate limit settings" />
  if (!settings) return null

  function updateRule(index: number, patch: Partial<RateLimitRule>) {
    if (!settings) return
    const next = settings.rate_limit.map((r, i) => (i === index ? { ...r, ...patch } : r))
    setSettings({ ...settings, rate_limit: next })
  }

  function addRule() {
    if (!settings) return
    const id = `rl-${Math.random().toString(36).slice(2, 8)}`
    setSettings({ ...settings, rate_limit: [...settings.rate_limit, { id, paths: ['/'], requests: 60, window: 60 }] })
  }

  function removeRule(index: number) {
    if (!settings) return
    setSettings({ ...settings, rate_limit: settings.rate_limit.filter((_, i) => i !== index) })
  }

  async function save() {
    if (!settings) return
    setError('')
    try {
      await api.put('/api/settings', settings)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
      reload()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <>
      <PageHeader
        title="Rate Limit"
        description="Fixed-window limits keyed by client IP and path. The limiter is bounded and fails open when saturated."
        actions={
          <>
            {saved ? <span className="text-sm text-[var(--success)]">Saved</span> : null}
            <Button variant="primary" onClick={() => void save()}>
              <span className="i-lucide-save" /> Save
            </Button>
          </>
        }
      />

      {error ? <Card className="mb-4 text-[var(--danger)]">{error}</Card> : null}

      <Card>
        <CardHeader
          title="Policies"
          subtitle="First matching policy applies. Use * as a suffix for prefix matching."
          actions={
            <Button size="sm" onClick={addRule}>
              <span className="i-lucide-plus" /> Add policy
            </Button>
          }
        />
        {settings.rate_limit.length === 0 ? (
          <EmptyState>No rate limit policies. Requests are not rate limited.</EmptyState>
        ) : (
          <div className="flex flex-col gap-3">
            {settings.rate_limit.map((rule, index) => (
              <div
                key={rule.id}
                className="grid gap-3 items-end p-3 rounded-lg"
                style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(8rem, 1fr))', background: 'var(--surface-muted)' }}
              >
                <Field label="Paths (comma separated)">
                  <Input
                    value={rule.paths.join(', ')}
                    onChange={(e) => updateRule(index, { paths: e.target.value.split(',').map((p) => p.trim()).filter(Boolean) })}
                    placeholder="/api/*, /login"
                  />
                </Field>
                <Field label="Requests">
                  <Input type="number" value={rule.requests} onChange={(e) => updateRule(index, { requests: Number(e.target.value) })} />
                </Field>
                <Field label="Window (seconds)">
                  <Input type="number" value={rule.window} onChange={(e) => updateRule(index, { window: Number(e.target.value) })} />
                </Field>
                <div className="flex items-center gap-2 justify-end">
                  <span className={s.mono}>id: {rule.id}</span>
                  <IconButton aria-label="Delete policy" title="Delete" onClick={() => removeRule(index)}>
                    <span className="i-lucide-trash-2" />
                  </IconButton>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  )
}
