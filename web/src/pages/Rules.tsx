import { Link } from '@tanstack/react-router'

import {
  ActionBadge,
  Button,
  Card,
  Chip,
  EmptyState,
  IconButton,
  PageHeader,
  SeverityBadge,
  Spinner,
  TableShell,
  Toggle,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import type { Rule } from '@/lib/types'

interface RulesResponse {
  rules: Rule[]
}

export function RulesPage() {
  const { data, loading, error, reload } = useApiQuery<RulesResponse>('/api/rules')
  const rules = data?.rules ?? []

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
    if (!window.confirm(`Delete rule "${rule.name}"?`)) return
    await api.del(`/api/rules/${encodeURIComponent(rule.id)}`)
    reload()
  }

  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection rules evaluated against every request. Changes apply immediately without a restart."
        actions={
          <Link to="/security/rules/new">
            <Button variant="primary">
              <span className="i-lucide-plus" /> New rule
            </Button>
          </Link>
        }
      />

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
                <th>Targets</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Action</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <Toggle checked={rule.enabled} onChange={(v) => void toggle(rule, v)} label={`Enable ${rule.name}`} />
                  </td>
                  <td>
                    <Link to="/security/rules/$ruleId" params={{ ruleId: rule.id }} className={s.link}>
                      {rule.name}
                    </Link>
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
                  <td className={s.targetCell}>
                    <div className={s.chipTight}>
                      {rule.targets.map((t) => (
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
                  <td>
                    <div className={s.rowEndTight}>
                      <Link to="/security/rules/$ruleId" params={{ ruleId: rule.id }}>
                        <IconButton aria-label="Edit" title="Edit">
                          <span className="i-lucide-pencil" />
                        </IconButton>
                      </Link>
                      <IconButton aria-label="Duplicate" title="Duplicate" onClick={() => void duplicate(rule)}>
                        <span className="i-lucide-copy" />
                      </IconButton>
                      <IconButton aria-label="Delete" title="Delete" onClick={() => void remove(rule)}>
                        <span className="i-lucide-trash-2" />
                      </IconButton>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableShell>
        )}
      </Card>
    </>
  )
}
