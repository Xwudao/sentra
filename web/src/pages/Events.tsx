import { useMemo, useState } from 'react'

import {
  ActionBadge,
  Button,
  Card,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  SeverityBadge,
  Spinner,
  TableShell,
} from '@/components/ui'
import s from '@/components/ui.module.scss'
import { useApiQuery } from '@/lib/api'
import { formatRelative, formatTime } from '@/lib/format'
import type { SecurityEvent } from '@/lib/types'

interface EventsResponse {
  events: SecurityEvent[]
  total: number
}

const PAGE_SIZE = 50

export function EventsPage() {
  const [filters, setFilters] = useState({ action: '', ip: '', rule: '', path: '' })
  const [applied, setApplied] = useState(filters)
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<SecurityEvent | null>(null)

  const path = useMemo(() => {
    const params = new URLSearchParams()
    if (applied.action) params.set('action', applied.action)
    if (applied.ip) params.set('ip', applied.ip)
    if (applied.rule) params.set('rule', applied.rule)
    if (applied.path) params.set('path', applied.path)
    params.set('limit', String(PAGE_SIZE))
    params.set('offset', String(offset))
    return `/api/events?${params.toString()}`
  }, [applied, offset])

  const { data, loading } = useApiQuery<EventsResponse>(path)
  const events = data?.events ?? []
  const total = data?.total ?? 0

  return (
    <>
      <PageHeader title="Events" description="Blocked and logged requests with their rule matches." />

      <Card className="mb-4">
        <form
          className="grid gap-3 items-end"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(10rem, 1fr))' }}
          onSubmit={(e) => {
            e.preventDefault()
            setOffset(0)
            setApplied(filters)
          }}
        >
          <Field label="Action">
            <Select value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}>
              <option value="">All</option>
              <option value="block">Blocked</option>
              <option value="log">Logged</option>
            </Select>
          </Field>
          <Field label="Client IP">
            <Input placeholder="1.2.3.4" value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} />
          </Field>
          <Field label="Rule">
            <Input placeholder="rule id" value={filters.rule} onChange={(e) => setFilters({ ...filters, rule: e.target.value })} />
          </Field>
          <Field label="Path contains">
            <Input placeholder="/admin" value={filters.path} onChange={(e) => setFilters({ ...filters, path: e.target.value })} />
          </Field>
          <div className="flex gap-2">
            <Button variant="primary" type="submit">
              <span className="i-lucide-search" /> Filter
            </Button>
            <Button
              type="button"
              onClick={() => {
                const cleared = { action: '', ip: '', rule: '', path: '' }
                setFilters(cleared)
                setApplied(cleared)
                setOffset(0)
              }}
            >
              Reset
            </Button>
          </div>
        </form>
      </Card>

      <Card>
        {loading && events.length === 0 ? (
          <Spinner label="Loading events" />
        ) : events.length === 0 ? (
          <EmptyState>No events match the current filters.</EmptyState>
        ) : (
          <TableShell>
            <thead>
              <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Method</th>
                <th>Path</th>
                <th>Action</th>
                <th>Score</th>
                <th>Rules</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.id} className={s.rowClickable} onClick={() => setSelected(ev)}>
                  <td title={formatTime(ev.timestamp)}>{formatRelative(ev.timestamp)}</td>
                  <td className={s.mono}>{ev.client_ip}</td>
                  <td className={s.mono}>{ev.method}</td>
                  <td className="max-w-[22rem] truncate" title={ev.path + (ev.query ? `?${ev.query}` : '')}>
                    {ev.path}
                  </td>
                  <td>
                    <ActionBadge action={ev.action} />
                  </td>
                  <td>{ev.score}</td>
                  <td className={s.mono}>{ev.matches.map((m) => m.rule_id).join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </TableShell>
        )}

        <div className="flex items-center justify-between gap-2 mt-4">
          <span className="text-xs text-[var(--text-muted)]">
            {total} event{total === 1 ? '' : 's'}
          </span>
          <div className="flex items-center gap-2">
            <Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              <span className="i-lucide-chevron-left" /> Prev
            </Button>
            <Button size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
              Next <span className="i-lucide-chevron-right" />
            </Button>
          </div>
        </div>
      </Card>

      <Modal open={!!selected} onClose={() => setSelected(null)} title="Event detail">
        {selected ? <EventDetail event={selected} /> : null}
      </Modal>
    </>
  )
}

function EventDetail({ event }: { event: SecurityEvent }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(9rem, 1fr))' }}>
        <Detail label="Time" value={formatTime(event.timestamp)} />
        <Detail label="Client IP" value={event.client_ip} />
        <Detail label="Method" value={event.method} />
        <Detail label="Status" value={String(event.status)} />
        <Detail label="Action" value={event.action} />
        <Detail label="Score" value={String(event.score)} />
        <Detail label="Host" value={event.host} />
        <Detail label="Duration" value={`${event.duration_us}µs`} />
      </div>
      <div>
        <div className={s.label}>Path</div>
        <div className={s.mono}>{event.path + (event.query ? `?${event.query}` : '')}</div>
      </div>
      {event.user_agent ? (
        <div>
          <div className={s.label}>User agent</div>
          <div className={s.mono}>{event.user_agent}</div>
        </div>
      ) : null}
      {event.body_truncated ? <p className="text-xs text-[var(--warning)]">Request body was truncated during inspection.</p> : null}
      <div>
        <div className={s.label}>Matched rules</div>
        {event.matches.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)]">No rule metadata.</p>
        ) : (
          <div className="flex flex-col gap-2 mt-1">
            {event.matches.map((m, i) => (
              <div key={`${m.rule_id}-${i}`} className="flex items-center gap-3 flex-wrap">
                <span className={s.mono}>{m.rule_id}</span>
                <span className="text-xs text-[var(--text-muted)]">target: {m.target}</span>
                <SeverityBadge severity={m.severity ?? 'low'} />
                <ActionBadge action={m.action} />
                <span className="text-xs text-[var(--text-muted)]">score {m.score}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className={s.label}>{label}</div>
      <div className="text-sm">{value}</div>
    </div>
  )
}
