import { useState } from 'react'

import {
  ActionBadge,
  Button,
  Card,
  CardHeader,
  Chip,
  Field,
  Input,
  PageHeader,
  Select,
  SeverityBadge,
  Textarea,
  cx,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api } from '@/lib/api'
import type { PlaygroundRequest, PlaygroundResponse } from '@/lib/types'

function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const idx = line.indexOf(':')
    if (idx <= 0) continue
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
  }
  return out
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const SAMPLE_HEADERS = 'Content-Type: application/json\nUser-Agent: Mozilla/5.0'

const SAMPLE: PlaygroundRequest = {
  method: 'POST',
  url: '/search?q=1%20UNION%20SELECT%20password',
  headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
  body: '{"name":"test"}',
  client_ip: '203.0.113.10',
}

export function PlaygroundPage() {
  const [form, setForm] = useState<PlaygroundRequest>({ ...SAMPLE, headers: { ...SAMPLE.headers } })
  const [headersText, setHeadersText] = useState(SAMPLE_HEADERS)
  const [result, setResult] = useState<PlaygroundResponse | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setRunning(true)
    setError('')
    try {
      const payload: PlaygroundRequest = { ...form, headers: parseHeaders(headersText) }
      const res = await api.post<PlaygroundResponse>('/api/rules/test', payload)
      setResult(res)
    } catch (e) {
      setError((e as Error).message)
      setResult(null)
    } finally {
      setRunning(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Rule Playground"
        description="Run the live ruleset against a synthetic request. This is a dry run: nothing is blocked and no security event is recorded."
      />

      <div className={s.grid} style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(22rem, 1fr))' }}>
        <Card>
          <CardHeader title="Request" subtitle="Simulated incoming request" />
          <form
            className={s.formCol}
            onSubmit={(e) => {
              e.preventDefault()
              void run()
            }}
          >
            <div className={s.formRow}>
              <Field label="Method">
                <Select
                  value={form.method}
                  onChange={(v) => setForm({ ...form, method: v })}
                  options={METHODS.map((m) => ({ value: m, label: m }))}
                />
              </Field>
              <Field label="URL">
                <Input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="/search?q=..." showClear />
              </Field>
            </div>
            <Field label="Client IP">
              <Input value={form.client_ip} onChange={(e) => setForm({ ...form, client_ip: e.target.value })} placeholder="203.0.113.10" showClear />
            </Field>
            <Field label="Headers (one per line)">
              <Textarea value={headersText} onChange={(e) => setHeadersText(e.target.value)} style={{ minHeight: '6rem' }} spellCheck={false} />
            </Field>
            <Field label="Body">
              <Textarea value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} style={{ minHeight: '6rem' }} spellCheck={false} />
            </Field>
            <div className={s.rowWrap}>
              <Button variant="primary" type="submit" disabled={running}>
                <span className="i-lucide-play" /> {running ? 'Running…' : 'Run test'}
              </Button>
              <Button
                type="button"
                onClick={() => {
                  setForm({ ...SAMPLE, headers: { ...SAMPLE.headers } })
                  setHeadersText(SAMPLE_HEADERS)
                }}
              >
                Sample attack
              </Button>
              <Button
                type="button"
                onClick={() => {
                  setForm({ method: 'GET', url: '/products?id=42', headers: {}, body: '', client_ip: '203.0.113.10' })
                  setHeadersText('')
                }}
              >
                Sample benign
              </Button>
            </div>
          </form>
        </Card>

        <Card>
          <CardHeader title="Decision" subtitle="Result of the live ruleset" />
          {error ? <p className={cx(s.textSm, s.dangerText)}>{error}</p> : null}
          {!result ? (
            <p className={cx(s.textSm, s.textMuted)}>Run a request to see the decision.</p>
          ) : (
            <div className={s.stack}>
              <div className={s.rowWrap}>
                <span className={s.decision} style={{ color: result.blocked ? 'var(--danger)' : 'var(--success)' }}>
                  {result.blocked ? 'BLOCK' : 'ALLOW'}
                </span>
                <span className={cx(s.textSm, s.textMuted)}>Score: {result.score}</span>
                {result.status ? <Chip>HTTP {result.status}</Chip> : null}
                {result.rate_limited ? <Chip>rate limited</Chip> : null}
                {result.body_truncated ? <Chip>body truncated</Chip> : null}
              </div>

              <div>
                <div className={s.label}>Matched rules</div>
                {result.matches.length === 0 ? (
                  <p className={cx(s.textSm, s.textMuted, s.mt2)}>No rules matched.</p>
                ) : (
                  <div className={s.matchList}>
                    {result.matches.map((m, i) => (
                      <div key={`${m.rule_id}-${i}`} className={s.inset}>
                        <div className={s.insetHead}>
                          <span className={s.strong}>{m.rule_name || m.rule_id}</span>
                          <span className={s.mono}>{m.rule_id}</span>
                          <SeverityBadge severity={m.severity ?? 'low'} />
                          <ActionBadge action={m.action} />
                          <Chip>score {m.score}</Chip>
                          <Chip>target: {m.target}</Chip>
                        </div>
                        {m.raw_value ? (
                          <div className={s.mb2}>
                            <div className={cx(s.label, s.mb2)}>Raw</div>
                            <pre className={s.pre}>{m.raw_value}</pre>
                          </div>
                        ) : null}
                        {m.transformed_value !== undefined ? (
                          <div>
                            <div className={cx(s.label, s.mb2)}>Transformed</div>
                            <pre className={s.pre}>{m.transformed_value}</pre>
                          </div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  )
}
