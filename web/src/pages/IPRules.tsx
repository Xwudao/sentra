import { useState } from 'react'

import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Field,
  IconButton,
  Input,
  PageHeader,
  Select,
  Spinner,
  TableShell,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { api, useApiQuery } from '@/lib/api'
import type { IPRule } from '@/lib/types'

interface IPRulesResponse {
  ip_rules: IPRule[]
}

export function IPRulesPage() {
  const { data, loading, reload } = useApiQuery<IPRulesResponse>('/api/ip-rules')
  const [form, setForm] = useState({ cidr: '', action: 'block', note: '' })
  const [error, setError] = useState('')

  const rules = data?.ip_rules ?? []

  async function add() {
    setError('')
    try {
      await api.post('/api/ip-rules', form)
      setForm({ cidr: '', action: 'block', note: '' })
      reload()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  async function remove(rule: IPRule) {
    if (!window.confirm(`Delete IP rule ${rule.cidr}?`)) return
    await api.del(`/api/ip-rules/${encodeURIComponent(rule.id)}`)
    reload()
  }

  return (
    <>
      <PageHeader
        title="IP Rules"
        description="Allow/block lists evaluated before WAF rules. Allow entries always win; forwarding headers are only trusted from configured proxies."
      />

      <Card className="mb-4">
        <CardHeader title="Add rule" subtitle="Accepts a CIDR range or a single IP address" />
        <form
          className="grid gap-3 items-end"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(10rem, 1fr))' }}
          onSubmit={(e) => {
            e.preventDefault()
            void add()
          }}
        >
          <Field label="CIDR / IP">
            <Input required value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} placeholder="203.0.113.0/24" />
          </Field>
          <Field label="Action">
            <Select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
              <option value="block">block</option>
              <option value="allow">allow</option>
            </Select>
          </Field>
          <Field label="Note">
            <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="optional" />
          </Field>
          <Button variant="primary" type="submit">
            <span className="i-lucide-plus" /> Add
          </Button>
        </form>
        {error ? <p className="text-sm text-[var(--danger)] mt-3">{error}</p> : null}
      </Card>

      <Card>
        {loading && rules.length === 0 ? (
          <Spinner label="Loading IP rules" />
        ) : rules.length === 0 ? (
          <EmptyState>No IP rules configured.</EmptyState>
        ) : (
          <TableShell>
            <thead>
              <tr>
                <th>CIDR</th>
                <th>Action</th>
                <th>Note</th>
                <th>Added</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td className={s.mono}>{rule.cidr}</td>
                  <td>
                    <Badge tone={rule.action === 'allow' ? 'allow' : 'block'}>{rule.action}</Badge>
                  </td>
                  <td>{rule.note || '—'}</td>
                  <td className="text-xs text-[var(--text-muted)]">{new Date(rule.created_at).toLocaleString()}</td>
                  <td className="text-right">
                    <IconButton aria-label="Delete" title="Delete" onClick={() => void remove(rule)}>
                      <span className="i-lucide-trash-2" />
                    </IconButton>
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
