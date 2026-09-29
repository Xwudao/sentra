import { useNavigate, useParams } from '@tanstack/react-router'
import { useEffect, useState } from 'react'

import {
  Button,
  Card,
  CardHeader,
  Chip,
  Field,
  Input,
  PageHeader,
  Select,
  Spinner,
  Tabs,
  Textarea,
  Toggle,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import type { Action, Operator, Rule, Severity } from '@/lib/types'

const TRANSFORMS = ['lowercase', 'url_decode', 'html_decode', 'remove_nulls', 'compress_whitespace', 'trim']
const OPERATORS: Operator[] = ['regex', 'contains', 'equals', 'prefix', 'suffix', 'keyword_set']
const TARGET_SUGGESTIONS = [
  'method',
  'host',
  'path',
  'uri',
  'query',
  'body',
  'header',
  'header:user-agent',
  'header:referer',
  'cookie',
  'cookie:session',
  'query_param:id',
  'json:user.name',
]

function emptyRule(): Rule {
  return {
    id: '',
    name: '',
    enabled: true,
    phase: 'request',
    targets: ['query'],
    operator: 'regex',
    value: '',
    transforms: ['url_decode', 'lowercase'],
    action: 'block',
    score: 10,
    severity: 'high',
    priority: 10,
    tags: [],
    description: '',
  }
}

export function RuleEditorPage() {
  const navigate = useNavigate()
  const params = useParams({ strict: false }) as { ruleId?: string }
  const isNew = !params.ruleId
  const { data, loading } = useApiQuery<Rule>(isNew ? null : `/api/rules/${encodeURIComponent(params.ruleId!)}`)
  const [rule, setRule] = useState<Rule>(emptyRule)
  const [tab, setTab] = useState<'form' | 'json'>('form')
  const [json, setJSON] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (data) setRule(data)
  }, [data])

  useEffect(() => {
    if (tab === 'json') setJSON(JSON.stringify(rule, null, 2))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab])

  function update<K extends keyof Rule>(key: K, value: Rule[K]) {
    setRule((r) => ({ ...r, [key]: value }))
  }

  async function save() {
    setError('')
    setSaving(true)
    try {
      const payload: Rule = { ...rule }
      if (isNew) {
        const created = await api.post<Rule>('/api/rules', payload)
        navigate({ to: '/security/rules' })
        return created
      }
      const updated = await api.put<Rule>(`/api/rules/${encodeURIComponent(rule.id)}`, payload)
      setRule(updated)
      navigate({ to: '/security/rules' })
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  if (!isNew && loading) return <Spinner label="Loading rule" />

  return (
    <>
      <PageHeader
        title={isNew ? 'New rule' : `Edit ${rule.name || rule.id}`}
        description="Rules are compiled on save; invalid rules are rejected without affecting the running ruleset."
        actions={
          <>
            <Button onClick={() => navigate({ to: '/security/rules' })}>Cancel</Button>
            <Button variant="primary" onClick={() => void save()} disabled={saving}>
              <span className="i-lucide-save" /> {saving ? 'Saving…' : 'Save rule'}
            </Button>
          </>
        }
      />

      {error ? <Card className="mb-4 text-[var(--danger)]">{error}</Card> : null}

      <Tabs
        tabs={[
          { id: 'form', label: 'Builder' },
          { id: 'json', label: 'Advanced JSON' },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'form' ? (
        <div className="grid gap-4" style={{ gridTemplateColumns: 'minmax(0, 1fr)' }}>
          <Card>
            <CardHeader title="Basics" />
            <div className={s.grid2}>
              <Field label="Name">
                <Input value={rule.name} onChange={(e) => update('name', e.target.value)} placeholder="Basic SQL injection" />
              </Field>
              <Field label="Rule ID" hint={isNew ? 'Auto-generated from the name if left blank.' : 'IDs are immutable.'}>
                <Input value={rule.id} disabled={!isNew} onChange={(e) => update('id', e.target.value)} placeholder="sqli-basic" />
              </Field>
              <Field label="Severity">
                <Select value={rule.severity} onChange={(e) => update('severity', e.target.value as Severity)}>
                  {['low', 'medium', 'high', 'critical'].map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Action">
                <Select value={rule.action} onChange={(e) => update('action', e.target.value as Action)}>
                  <option value="block">block</option>
                  <option value="log">log</option>
                  <option value="allow">allow (whitelist)</option>
                </Select>
              </Field>
              <Field label="Score">
                <Input type="number" value={rule.score} onChange={(e) => update('score', Number(e.target.value))} />
              </Field>
              <Field label="Priority" hint="Higher priority groups are evaluated first.">
                <Input type="number" value={rule.priority} onChange={(e) => update('priority', Number(e.target.value))} />
              </Field>
            </div>
            <div className="mt-3">
              <Field label="Description">
                <Input value={rule.description} onChange={(e) => update('description', e.target.value)} />
              </Field>
            </div>
            <div className="mt-3">
              <Field label="Tags (comma separated)">
                <Input
                  value={rule.tags.join(', ')}
                  onChange={(e) => update('tags', e.target.value.split(',').map((t) => t.trim()).filter(Boolean))}
                />
              </Field>
            </div>
            <div className="flex items-center gap-3 mt-4">
              <Toggle checked={rule.enabled} onChange={(v) => update('enabled', v)} label="Enabled" />
              <span className="text-sm">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
          </Card>

          <Card>
            <CardHeader title="Match" subtitle="Where to look and how to compare" />
            <Field label="Targets">
              <TargetsEditor targets={rule.targets} onChange={(t) => update('targets', t)} />
            </Field>
            <div className={s.grid2} style={{ marginTop: 'var(--space-4)' }}>
              <Field label="Operator">
                <Select value={rule.operator} onChange={(e) => update('operator', e.target.value as Operator)}>
                  {OPERATORS.map((op) => (
                    <option key={op} value={op}>
                      {op}
                    </option>
                  ))}
                </Select>
              </Field>
              {rule.operator === 'keyword_set' ? (
                <Field label="Keywords (one per line)">
                  <Textarea
                    value={(rule.values ?? []).join('\n')}
                    onChange={(e) => update('values', e.target.value.split('\n').map((v) => v.trim()).filter(Boolean))}
                  />
                </Field>
              ) : (
                <Field label="Value">
                  <Input value={rule.value} onChange={(e) => update('value', e.target.value)} placeholder="pattern or literal" />
                </Field>
              )}
            </div>
            <div className="mt-4">
              <div className={s.label}>Transforms</div>
              <div className="flex flex-wrap gap-2 mt-2">
                {TRANSFORMS.map((t) => {
                  const active = rule.transforms.includes(t)
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() =>
                        update(
                          'transforms',
                          active ? rule.transforms.filter((x) => x !== t) : [...rule.transforms, t],
                        )
                      }
                      style={{ cursor: 'pointer', border: 'none', background: 'none', padding: 0 }}
                    >
                      <span className={s.badge} style={active ? { background: 'var(--accent-soft)', color: 'var(--accent)' } : undefined}>
                        {active ? <span className="i-lucide-check" /> : null}
                        {t}
                      </span>
                    </button>
                  )
                })}
              </div>
              <p className={s.hint}>Transforms run in the order listed. {rule.transforms.join(' → ') || 'none'}</p>
            </div>
          </Card>
        </div>
      ) : (
        <Card>
          <CardHeader
            title="Rule JSON"
            subtitle="Edit the raw document and apply it to the builder"
            actions={
              <Button
                onClick={() => {
                  try {
                    const parsed = JSON.parse(json) as Rule
                    setRule({ ...emptyRule(), ...parsed })
                    setTab('form')
                    setError('')
                  } catch (e) {
                    setError((e as Error).message)
                  }
                }}
              >
                Apply JSON
              </Button>
            }
          />
          <Textarea value={json} onChange={(e) => setJSON(e.target.value)} spellCheck={false} style={{ minHeight: '24rem' }} />
        </Card>
      )}
    </>
  )
}

function TargetsEditor({ targets, onChange }: { targets: string[]; onChange: (t: string[]) => void }) {
  const [input, setInput] = useState('')
  function add(value: string) {
    const v = value.trim()
    if (!v || targets.includes(v)) return
    onChange([...targets, v])
    setInput('')
  }
  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-2 flex-wrap">
        {targets.map((t) => (
          <span key={t} className="flex items-center gap-1">
            <Chip>{t}</Chip>
            <button
              type="button"
              aria-label={`Remove ${t}`}
              onClick={() => onChange(targets.filter((x) => x !== t))}
              style={{ cursor: 'pointer', border: 'none', background: 'none', color: 'var(--text-muted)' }}
            >
              <span className="i-lucide-x" />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <Input
          value={input}
          list="target-suggestions"
          placeholder="add target, e.g. header:user-agent"
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              add(input)
            }
          }}
        />
        <datalist id="target-suggestions">
          {TARGET_SUGGESTIONS.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
        <Button type="button" onClick={() => add(input)}>
          <span className="i-lucide-plus" /> Add
        </Button>
      </div>
    </div>
  )
}
