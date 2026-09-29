import { useNavigate, useParams } from '@tanstack/react-router'
import { useEffect, useState } from 'react'

import {
  Button,
  Card,
  CardHeader,
  Chip,
  Field,
  Input,
  InputNumber,
  PageHeader,
  Select,
  Spinner,
  Tabs,
  Textarea,
  Toggle,
  cx,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import type { Action, Operator, Rule, Severity } from '@/lib/types'

const TRANSFORMS = ['lowercase', 'url_decode', 'html_decode', 'remove_nulls', 'compress_whitespace', 'trim']
const OPERATORS: Operator[] = ['regex', 'contains', 'equals', 'prefix', 'suffix', 'keyword_set']
const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']
const ACTION_OPTIONS = [
  { value: 'block', label: 'block' },
  { value: 'log', label: 'log' },
  { value: 'allow', label: 'allow (whitelist)' },
]
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

      {error ? <Card className={cx(s.mb4, s.dangerText)}>{error}</Card> : null}

      <Tabs
        tabs={[
          { id: 'form', label: 'Builder' },
          { id: 'json', label: 'Advanced JSON' },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'form' ? (
        <div className={s.stack}>
          <Card>
            <CardHeader title="Basics" />
            <div className={s.grid2}>
              <Field label="Name">
                <Input value={rule.name} onChange={(e) => update('name', e.target.value)} placeholder="Basic SQL injection" showClear />
              </Field>
              <Field label="Rule ID" hint={isNew ? 'Auto-generated from the name if left blank.' : 'IDs are immutable.'}>
                <Input value={rule.id} disabled={!isNew} onChange={(e) => update('id', e.target.value)} placeholder="sqli-basic" />
              </Field>
              <Field label="Severity">
                <Select
                  value={rule.severity}
                  onChange={(v) => update('severity', v as Severity)}
                  options={SEVERITIES.map((v) => ({ value: v, label: v }))}
                />
              </Field>
              <Field label="Action">
                <Select value={rule.action} onChange={(v) => update('action', v as Action)} options={ACTION_OPTIONS} />
              </Field>
              <Field label="Score">
                <InputNumber value={rule.score} onChange={(v) => update('score', v ?? 0)} />
              </Field>
              <Field label="Priority" hint="Higher priority groups are evaluated first.">
                <InputNumber value={rule.priority} onChange={(v) => update('priority', v ?? 0)} />
              </Field>
            </div>
            <div className={s.mt3}>
              <Field label="Description">
                <Input value={rule.description} onChange={(e) => update('description', e.target.value)} />
              </Field>
            </div>
            <div className={s.mt3}>
              <Field label="Tags (comma separated)">
                <Input
                  value={rule.tags.join(', ')}
                  onChange={(e) => update('tags', e.target.value.split(',').map((t) => t.trim()).filter(Boolean))}
                />
              </Field>
            </div>
            <div className={cx(s.row, s.mt4)}>
              <Toggle checked={rule.enabled} onChange={(v) => update('enabled', v)} label="Enabled" />
              <span className={s.textSm}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
          </Card>

          <Card>
            <CardHeader title="Match" subtitle="Where to look and how to compare" />
            <Field label="Targets">
              <TargetsEditor targets={rule.targets} onChange={(t) => update('targets', t)} />
            </Field>
            <div className={cx(s.grid2, s.mt4)}>
              <Field label="Operator">
                <Select
                  value={rule.operator}
                  onChange={(v) => update('operator', v as Operator)}
                  options={OPERATORS.map((op) => ({ value: op, label: op }))}
                />
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
            <div className={s.mt4}>
              <div className={s.label}>Transforms</div>
              <div className={s.transformList}>
                {TRANSFORMS.map((t) => {
                  const active = rule.transforms.includes(t)
                  return (
                    <button
                      key={t}
                      type="button"
                      className={s.transformButton}
                      onClick={() =>
                        update(
                          'transforms',
                          active ? rule.transforms.filter((x) => x !== t) : [...rule.transforms, t],
                        )
                      }
                    >
                      <span className={cx(s.badge, active && s.transformActive)}>
                        {active ? <span className="i-lucide-check" /> : null}
                        {t}
                      </span>
                    </button>
                  )
                })}
              </div>
              <p className={cx(s.hint, s.mt2)}>Transforms run in the order listed. {rule.transforms.join(' → ') || 'none'}</p>
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
    <div className={s.stackTight}>
      <div className={s.rowWrap}>
        {targets.map((t) => (
          <span key={t} className={s.row}>
            <Chip>{t}</Chip>
            <button type="button" className={s.iconOnly} aria-label={`Remove ${t}`} onClick={() => onChange(targets.filter((x) => x !== t))}>
              <span className="i-lucide-x" />
            </button>
          </span>
        ))}
      </div>
      <div className={s.row}>
        <Input
          className={s.grow}
          value={input}
          list="target-suggestions"
          placeholder="add target, e.g. header:user-agent"
          showClear
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
