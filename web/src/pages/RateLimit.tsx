import { useEffect, useState } from 'react'

import { Button, Card, CardHeader, EmptyState, Field, IconButton, Input, InputNumber, PageHeader, Spinner, cx } from '@/components/ui'
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
            {saved ? <span className={cx(s.textSm, s.successText)}>Saved</span> : null}
            <Button variant="primary" onClick={() => void save()}>
              <span className="i-lucide-save" /> Save
            </Button>
          </>
        }
      />

      {error ? <Card className={cx(s.mb4, s.dangerText)}>{error}</Card> : null}

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
          <EmptyState
            icon="i-lucide-gauge"
            title="No rate limit policies"
            description="Requests are currently not rate limited."
            action={
              <Button variant="primary" size="sm" onClick={addRule}>
                <span className="i-lucide-plus" /> Add policy
              </Button>
            }
          />
        ) : (
          <div className={s.stackTight}>
            {settings.rate_limit.map((rule, index) => (
              <div
                key={rule.id}
                className={s.policyRow}
                style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(8rem, 1fr))' }}
              >
                <Field label="Paths (comma separated)">
                  <Input
                    value={rule.paths.join(', ')}
                    onChange={(e) => updateRule(index, { paths: e.target.value.split(',').map((p) => p.trim()).filter(Boolean) })}
                    placeholder="/api/*, /login"
                    showClear
                  />
                </Field>
                <Field label="Requests">
                  <InputNumber value={rule.requests} onChange={(v) => updateRule(index, { requests: v ?? 0 })} />
                </Field>
                <Field label="Window (seconds)">
                  <InputNumber value={rule.window} onChange={(v) => updateRule(index, { window: v ?? 0 })} />
                </Field>
                <div className={s.rowEnd}>
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
