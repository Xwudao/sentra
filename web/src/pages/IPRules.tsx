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
  Textarea,
  cx,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { Popconfirm } from '@/components/Popconfirm'
import { api, useApiQuery } from '@/lib/api'
import type { IPRule } from '@/lib/types'

interface IPRulesResponse {
  ip_rules: IPRule[]
}

const ACTION_OPTIONS = [
  { value: 'block', label: 'block' },
  { value: 'allow', label: 'allow' },
]

export function IPRulesPage() {
  const { data, loading, reload } = useApiQuery<IPRulesResponse>('/api/ip-rules')
  const [form, setForm] = useState({ cidr: '', action: 'block', note: '' })
  const [error, setError] = useState('')
  const [batchMode, setBatchMode] = useState(false)
  const [batchText, setBatchText] = useState('')
  const [batchAction, setBatchAction] = useState('block')
  const [batchNote, setBatchNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [success, setSuccess] = useState('')

  const rules = data?.ip_rules ?? []

  async function add() {
    if (submitting) return
    setError('')
    setSuccess('')
    setSubmitting(true)
    try {
      if (batchMode) {
        const cidrs = batchText.split(/[\s,;]+/).filter(Boolean)
        if (cidrs.length === 0 || cidrs.length > 1000) {
          setError('Enter 1 to 1000 IP addresses or CIDR ranges.')
          return
        }
        const result = await api.post<{ created: number }>('/api/ip-rules/batch', { cidrs, action: batchAction, note: batchNote })
        setBatchText('')
        setSuccess(`Added ${result.created} IP rules.`)
      } else {
        await api.post('/api/ip-rules', form)
        setForm({ cidr: '', action: 'block', note: '' })
      }
      reload()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  async function remove(rule: IPRule) {
    await api.del(`/api/ip-rules/${encodeURIComponent(rule.id)}`)
    reload()
  }

  return (
    <>
      <PageHeader
        title="IP Rules"
        description="Allow/block lists evaluated before WAF rules. Allow entries always win; forwarding headers are only trusted from configured proxies."
      />

      <Card className={s.mb4}>
        <CardHeader
          title={batchMode ? 'Add rules in bulk' : 'Add rule'}
          subtitle={batchMode ? 'Paste up to 1000 IP addresses or CIDR ranges, separated by lines, commas or spaces.' : 'Accepts a CIDR range or a single IP address'}
          actions={<Button type="button" onClick={() => { setBatchMode(!batchMode); setError(''); setSuccess('') }}>{batchMode ? 'Single add' : 'Bulk add'}</Button>}
        />
        <form
          className={batchMode ? s.stack : s.formGrid}
          onSubmit={(e) => {
            e.preventDefault()
            void add()
          }}
        >
          {batchMode ? (
            <>
              <Field label="CIDR / IP list">
                <Textarea required rows={7} value={batchText} onChange={(e) => setBatchText(e.target.value)} placeholder={'203.0.113.1\n203.0.113.0/24\n2001:db8::1'} />
              </Field>
              <div className={s.gridAuto}>
                <Field label="Action">
                  <Select value={batchAction} onChange={setBatchAction} options={ACTION_OPTIONS} />
                </Field>
                <Field label="Note (applies to all)">
                  <Input value={batchNote} onChange={(e) => setBatchNote(e.target.value)} placeholder="optional" showClear />
                </Field>
              </div>
            </>
          ) : (
            <>
              <Field label="CIDR / IP">
                <Input required value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} placeholder="203.0.113.0/24" showClear />
              </Field>
              <Field label="Action">
                <Select value={form.action} onChange={(v) => setForm({ ...form, action: v })} options={ACTION_OPTIONS} />
              </Field>
              <Field label="Note">
                <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="optional" showClear />
              </Field>
            </>
          )}
          <Button variant="primary" type="submit" disabled={submitting}>
            <span className="i-lucide-plus" /> {submitting ? 'Adding…' : batchMode ? 'Add all' : 'Add'}
          </Button>
        </form>
        {error ? <p role="alert" className={cx(s.textSm, s.dangerText, s.mt3)}>{error}</p> : null}
        {success ? <p role="status" className={cx(s.textSm, s.successText, s.mt3)}>{success}</p> : null}
      </Card>

      <Card flush>
        {loading && rules.length === 0 ? (
          <div className={s.cardSection}>
            <Spinner label="Loading IP rules" />
          </div>
        ) : rules.length === 0 ? (
          <div className={s.cardSection}>
            <EmptyState icon="i-lucide-network" title="No IP rules" description="Add an allow or block entry to filter traffic before WAF rules run." />
          </div>
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
                  <td className={cx(s.textXs, s.textMuted)}>{new Date(rule.created_at).toLocaleString()}</td>
                  <td className={s.textRight}>
                    <Popconfirm title={`Delete IP rule ${rule.cidr}?`} message="This action cannot be undone." onConfirm={() => void remove(rule)}>
                      <IconButton aria-label="Delete" title="Delete" type="button">
                        <span className="i-lucide-trash-2" />
                      </IconButton>
                    </Popconfirm>
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
