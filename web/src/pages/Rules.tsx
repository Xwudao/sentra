import { Link } from '@tanstack/react-router'
import { useState } from 'react'

import {
  ActionBadge,
  Button,
  Card,
  Chip,
  Detail,
  EmptyState,
  IconButton,
  Modal,
  PageHeader,
  SeverityBadge,
  Spinner,
  TableShell,
  Toggle,
  cx,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { Popconfirm } from '@/components/Popconfirm'
import { api, useApiQuery } from '@/lib/api'
import type { Rule } from '@/lib/types'

interface RulesResponse {
  rules: Rule[]
}

export function RulesPage() {
  const { data, loading, error, reload } = useApiQuery<RulesResponse>('/api/rules')
  const [selected, setSelected] = useState<Rule | null>(null)
  const [restoring, setRestoring] = useState(false)
  const [restoreError, setRestoreError] = useState('')
  const rules = data?.rules ?? []

  async function restoreDefaults() {
    setRestoring(true)
    setRestoreError('')
    try {
      await api.post('/api/rules/restore')
      setSelected(null)
      reload()
    } catch (e) {
      setRestoreError((e as Error).message)
    } finally {
      setRestoring(false)
    }
  }

  async function toggle(rule: Rule, enabled: boolean) {
    await api.put(`/api/rules/${encodeURIComponent(rule.id)}`, { ...rule, enabled })
    reload()
  }

  async function duplicate(rule: Rule) {
    const copy: Rule = { ...rule, id: `${rule.id}-copy`, name: `${rule.name} (copy)`, enabled: false }
    await api.post('/api/rules', copy)
    reload()
  }

  async function remove(rule: Rule) {
    await api.del(`/api/rules/${encodeURIComponent(rule.id)}`)
    reload()
  }

  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection rules evaluated against every request. Changes apply immediately without a restart."
        actions={
          <>
            <Popconfirm
              title="Restore default rules?"
              message="This will remove all custom rules and reset modified rules to their built-in defaults. This cannot be undone."
              confirmText="Restore defaults"
              onConfirm={() => void restoreDefaults()}
            >
              <Button type="button" disabled={restoring}>
                <span className="i-lucide-rotate-ccw" /> {restoring ? 'Restoring…' : 'Restore defaults'}
              </Button>
            </Popconfirm>
            <Link to="/security/rules/new">
              <Button variant="primary">
                <span className="i-lucide-plus" /> New rule
              </Button>
            </Link>
          </>
        }
      />

      {restoreError ? <Card className={cx(s.mb4, s.dangerText)}>Failed to restore default rules: {restoreError}</Card> : null}
      {error ? <Card className={s.mb4}>Failed to load rules: {error.message}</Card> : null}

      <Card flush>
        {loading && rules.length === 0 ? (
          <div className={s.cardSection}>
            <Spinner label="Loading rules" />
          </div>
        ) : rules.length === 0 ? (
          <div className={s.cardSection}>
            <EmptyState
              icon="i-lucide-shield-plus"
              title="No rules yet"
              description="Create your first detection rule to start protecting traffic."
              action={
                <Link to="/security/rules/new">
                  <Button variant="primary">
                    <span className="i-lucide-plus" /> New rule
                  </Button>
                </Link>
              }
            />
          </div>
        ) : (
          <TableShell>
            <thead>
              <tr>
                <th>On</th>
                <th>Name</th>
                <th>ID</th>
                <th>Operator</th>
                <th>Value</th>
                <th>Targets</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Action</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className={s.rowClickable} onClick={() => setSelected(rule)}>
                  <td onClick={(e) => e.stopPropagation()}>
                    <Toggle checked={rule.enabled} onChange={(v) => void toggle(rule, v)} label={`Enable ${rule.name}`} />
                  </td>
                  <td>
                    <span className={s.link}>{rule.name}</span>
                    {rule.tags?.length ? (
                      <div className={s.tagRow}>
                        {rule.tags.map((tag) => (
                          <Chip key={tag}>{tag}</Chip>
                        ))}
                      </div>
                    ) : null}
                  </td>
                  <td className={s.mono}>{rule.id}</td>
                  <td className={s.mono}>{rule.operator}</td>
                  <td className={s.pathCell}>
                    <span className={cx(s.mono, s.textMuted)} title={valueTitle(rule)}>
                      {valuePreview(rule)}
                    </span>
                  </td>
                  <td className={s.targetCell}>
                    <div className={s.chipTight}>
                      {(rule.targets ?? []).map((t) => (
                        <Chip key={t}>{t}</Chip>
                      ))}
                    </div>
                  </td>
                  <td>
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td>{rule.score}</td>
                  <td>
                    <ActionBadge action={rule.action} />
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div className={s.rowEndTight}>
                      <IconButton aria-label="View details" title="View details" onClick={() => setSelected(rule)}>
                        <span className="i-lucide-eye" />
                      </IconButton>
                      <Link to="/security/rules/$ruleId" params={{ ruleId: rule.id }}>
                        <IconButton aria-label="Edit" title="Edit">
                          <span className="i-lucide-pencil" />
                        </IconButton>
                      </Link>
                      <IconButton aria-label="Duplicate" title="Duplicate" onClick={() => void duplicate(rule)}>
                        <span className="i-lucide-copy" />
                      </IconButton>
                      <Popconfirm title={`Delete rule "${rule.name}"?`} message="This action cannot be undone." onConfirm={() => void remove(rule)}>
                        <IconButton aria-label="Delete" title="Delete" type="button">
                          <span className="i-lucide-trash-2" />
                        </IconButton>
                      </Popconfirm>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableShell>
        )}
      </Card>

      <Modal open={!!selected} onClose={() => setSelected(null)} title={selected?.name ?? 'Rule detail'}>
        {selected ? <RuleDetail rule={selected} /> : null}
      </Modal>
    </>
  )
}

function valuePreview(rule: Rule): string {
  if (rule.operator === 'keyword_set') {
    const count = rule.values?.length ?? 0
    return count === 1 ? '1 keyword' : `${count} keywords`
  }
  return rule.value || '—'
}

function valueTitle(rule: Rule): string {
  if (rule.operator === 'keyword_set') return (rule.values ?? []).join('\n')
  return rule.value
}

function RuleDetail({ rule }: { rule: Rule }) {
  const keywords = rule.values ?? []
  return (
    <div className={s.stack}>
      <div className={s.gridAutoSm}>
        <Detail
          label="Status"
          value={
            <span className={rule.enabled ? s.successText : s.textMuted}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
          }
        />
        <Detail label="Rule ID" value={<span className={s.mono}>{rule.id}</span>} />
        <Detail label="Operator" value={rule.operator} />
        <Detail label="Severity" value={<SeverityBadge severity={rule.severity} />} />
        <Detail label="Action" value={<ActionBadge action={rule.action} />} />
        <Detail label="Score" value={String(rule.score)} />
        <Detail label="Priority" value={String(rule.priority)} />
        <Detail label="Phase" value={rule.phase} />
      </div>

      <div>
        <div className={cx(s.label, s.mb2)}>{rule.operator === 'keyword_set' ? 'Keywords' : 'Value'}</div>
        {rule.operator === 'keyword_set' ? (
          keywords.length ? (
            <div className={s.chipTight}>
              {keywords.map((keyword) => (
                <Chip key={keyword}>{keyword}</Chip>
              ))}
            </div>
          ) : (
            <p className={cx(s.textSm, s.textMuted)}>No keywords defined.</p>
          )
        ) : (
          <pre className={s.pre}>{rule.value || '—'}</pre>
        )}
      </div>

      <div>
        <div className={cx(s.label, s.mb2)}>Targets</div>
        {rule.targets?.length ? (
          <div className={s.chipTight}>
            {(rule.targets ?? []).map((target) => (
              <Chip key={target}>{target}</Chip>
            ))}
          </div>
        ) : (
          <p className={cx(s.textSm, s.textMuted)}>No targets defined.</p>
        )}
      </div>

      <div>
        <div className={cx(s.label, s.mb2)}>Transforms</div>
        {rule.transforms?.length ? (
          <>
            <div className={s.chipTight}>
              {(rule.transforms ?? []).map((transform) => (
                <Chip key={transform}>{transform}</Chip>
              ))}
            </div>
            <p className={cx(s.hint, s.mt2)}>Runs in order: {(rule.transforms ?? []).join(' → ')}</p>
          </>
        ) : (
          <p className={cx(s.textSm, s.textMuted)}>None</p>
        )}
      </div>

      {rule.tags?.length ? (
        <div>
          <div className={cx(s.label, s.mb2)}>Tags</div>
          <div className={s.chipTight}>
            {(rule.tags ?? []).map((tag) => (
              <Chip key={tag}>{tag}</Chip>
            ))}
          </div>
        </div>
      ) : null}

      {rule.description ? (
        <div>
          <div className={cx(s.label, s.mb2)}>Description</div>
          <div className={s.textSm}>{rule.description}</div>
        </div>
      ) : null}
    </div>
  )
}
