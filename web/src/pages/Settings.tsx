import { useEffect, useState } from 'react'

import { Button, Card, CardHeader, Chip, Field, Input, InputNumber, PageHeader, Select, Spinner, cx } from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import type { Settings } from '@/lib/types'

const BODY_LIMIT_OPTIONS = [
  { value: 'allow', label: 'allow (inspect trivially, forward)' },
  { value: 'block', label: 'block' },
]

export function SettingsPage() {
  const { data, loading, reload } = useApiQuery<Settings>('/api/settings')
  const [settings, setSettings] = useState<Settings | null>(null)
  const [mib, setMib] = useState(2)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!data) return
    setSettings(data)
    setMib(Math.round((data.max_request_body_size / (1024 * 1024)) * 100) / 100)
  }, [data])

  if (loading && !settings) return <Spinner label="Loading settings" />
  if (!settings) return null

  async function save() {
    if (!settings) return
    setError('')
    try {
      const payload: Settings = {
        ...settings,
        max_request_body_size: Math.round(mib * 1024 * 1024),
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
            {saved ? <span className={cx(s.textSm, s.successText)}>Saved</span> : null}
            <Button variant="primary" onClick={() => void save()}>
              <span className="i-lucide-save" /> Save
            </Button>
          </>
        }
      />

      {error ? <Card className={cx(s.mb4, s.dangerText)}>{error}</Card> : null}

      <Card className={s.mb4}>
        <CardHeader title="Request inspection" subtitle="Controls how request bodies are handled" />
        <div className={s.gridAuto}>
          <Field label="Max inspected body (MiB)" hint={formatBytes(settings.max_request_body_size)}>
            <InputNumber step={0.5} min={0} value={mib} onChange={(v) => setMib(v ?? 0)} />
          </Field>
          <Field label="When the body exceeds the window">
            <Select
              value={settings.body_limit_action}
              onChange={(v) => setSettings({ ...settings, body_limit_action: v as Settings['body_limit_action'] })}
              options={BODY_LIMIT_OPTIONS}
            />
          </Field>
        </div>
      </Card>

      <Card className={s.mb4}>
        <CardHeader title="Detection" subtitle="Anomaly scoring and proxy trust" />
        <div className={s.gridAuto}>
          <Field label="Anomaly threshold" hint="0 disables threshold blocking; block rules still block.">
            <InputNumber
              min={0}
              value={settings.anomaly_threshold}
              onChange={(v) => setSettings({ ...settings, anomaly_threshold: v ?? 0 })}
            />
          </Field>
          <Field label="Client IP header" hint="Only honoured from trusted proxies.">
            <Input
              value={settings.client_ip_header}
              onChange={(e) => setSettings({ ...settings, client_ip_header: e.target.value })}
              placeholder="CF-Connecting-IP"
              showClear
            />
          </Field>
        </div>
        <div className={s.mt4}>
          <div className={cx(s.label, s.mb2)}>Trusted proxies (from server config)</div>
          {settings.trusted_proxies && settings.trusted_proxies.length > 0 ? (
            <div className={s.rowWrap}>
              {settings.trusted_proxies.map((p) => (
                <Chip key={p}>{p}</Chip>
              ))}
            </div>
          ) : (
            <p className={cx(s.textSm, s.textMuted)}>
              None configured. Forwarding headers (X-Forwarded-For, client IP header) are ignored and the direct peer address is used.
            </p>
          )}
        </div>
      </Card>
    </>
  )
}
