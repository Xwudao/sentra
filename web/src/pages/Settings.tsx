import { useEffect, useState } from 'react'

import { Button, Card, CardHeader, Chip, Field, Input, PageHeader, Select, Spinner } from '@/components/ui'
import { api, useApiQuery } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import type { Settings } from '@/lib/types'

export function SettingsPage() {
  const { data, loading, reload } = useApiQuery<Settings>('/api/settings')
  const [settings, setSettings] = useState<Settings | null>(null)
  const [mib, setMib] = useState('2')
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!data) return
    setSettings(data)
    setMib(String(Math.round((data.max_request_body_size / (1024 * 1024)) * 100) / 100))
  }, [data])

  if (loading && !settings) return <Spinner label="Loading settings" />
  if (!settings) return null

  async function save() {
    if (!settings) return
    setError('')
    try {
      const payload: Settings = {
        ...settings,
        max_request_body_size: Math.round(Number(mib) * 1024 * 1024),
      }
      const updated = await api.put<Settings>('/api/settings', payload)
      setSettings(updated)
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
        title="Settings"
        description="Global engine configuration. Changes are applied to the running engine immediately."
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

      <Card className="mb-4">
        <CardHeader title="Request inspection" subtitle="Controls how request bodies are handled" />
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(12rem, 1fr))' }}>
          <Field label="Max inspected body (MiB)" hint={formatBytes(settings.max_request_body_size)}>
            <Input type="number" step="0.5" min="0" value={mib} onChange={(e) => setMib(e.target.value)} />
          </Field>
          <Field label="When the body exceeds the window">
            <Select
              value={settings.body_limit_action}
              onChange={(e) => setSettings({ ...settings, body_limit_action: e.target.value as Settings['body_limit_action'] })}
            >
              <option value="allow">allow (inspect trivially, forward)</option>
              <option value="block">block</option>
            </Select>
          </Field>
        </div>
      </Card>

      <Card className="mb-4">
        <CardHeader title="Detection" subtitle="Anomaly scoring and proxy trust" />
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(12rem, 1fr))' }}>
          <Field label="Anomaly threshold" hint="0 disables threshold blocking; block rules still block.">
            <Input
              type="number"
              min="0"
              value={settings.anomaly_threshold}
              onChange={(e) => setSettings({ ...settings, anomaly_threshold: Number(e.target.value) })}
            />
          </Field>
          <Field label="Client IP header" hint="Only honoured from trusted proxies.">
            <Input
              value={settings.client_ip_header}
              onChange={(e) => setSettings({ ...settings, client_ip_header: e.target.value })}
              placeholder="CF-Connecting-IP"
            />
          </Field>
        </div>
        <div className="mt-4">
          <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2">Trusted proxies (from server config)</div>
          {settings.trusted_proxies && settings.trusted_proxies.length > 0 ? (
            <div className="flex gap-1 flex-wrap">
              {settings.trusted_proxies.map((p) => (
                <Chip key={p}>{p}</Chip>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[var(--text-muted)]">
              None configured. Forwarding headers (X-Forwarded-For, client IP header) are ignored and the direct peer address is used.
            </p>
          )}
        </div>
      </Card>
    </>
  )
}
