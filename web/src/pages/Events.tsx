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
  Pagination,
  Select,
  SeverityBadge,
  Spinner,
  TableShell,
  cx,
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

const ACTION_FILTERS = [
  { value: '', label: 'All' },
  { value: 'block', label: 'Blocked' },
  { value: 'log', label: 'Logged' },
]

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

  function resetFilters() {
    const cleared = { action: '', ip: '', rule: '', path: '' }
    setFilters(cleared)
    setApplied(cleared)
    setOffset(0)
  }

  return (
    <>
      <PageHeader title="Events" description="Blocked and logged requests with their rule matches." />

      <Card className={s.mb4}>
        <form
          className={s.formGrid}
          onSubmit={(e) => {
            e.preventDefault()
            setOffset(0)
            setApplied(filters)
          }}
        >
          <Field label="Action">
            <Select value={filters.action} onChange={(v) => setFilters({ ...filters, action: v })} options={ACTION_FILTERS} />
          </Field>
          <Field label="Client IP">
            <Input placeholder="1.2.3.4" value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} showClear />
          </Field>
          <Field label="Rule">
            <Input placeholder="rule id" value={filters.rule} onChange={(e) => setFilters({ ...filters, rule: e.target.value })} showClear />
          </Field>
          <Field label="Path contains">
            <Input placeholder="/admin" value={filters.path} onChange={(e) => setFilters({ ...filters, path: e.target.value })} showClear />
          </Field>
          <div className={s.row}>
            <Button variant="primary" type="submit">
              <span className="i-lucide-search" /> Filter
            </Button>
            <Button
              type="button"
              onClick={resetFilters}
            >
              Reset
            </Button>
          </div>
        </form>
      </Card>

      <Card flush>
        {loading && events.length === 0 ? (
          <div className={s.cardSection}>
            <Spinner label="Loading events" />
          </div>
        ) : events.length === 0 ? (
          <div className={s.cardSection}>
            <EmptyState
              icon="i-lucide-search-x"
              title="No events found"
              description="Try adjusting or clearing the filters above."
              action={
                <Button size="sm" onClick={resetFilters}>
                  Reset filters
                </Button>
              }
            />
          </div>
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
                  <td className={s.pathCell} title={ev.path + (ev.query ? `?${ev.query}` : '')}>
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

        <div className={s.cardSection}>
          <Pagination offset={offset} pageSize={PAGE_SIZE} total={total} onChange={setOffset} />
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
    <div className={s.stack}>
      <div className={s.gridAutoSm}>
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
        <div className={cx(s.label, s.mb2)}>Path</div>
        <div className={s.pre}>{event.path + (event.query ? `?${event.query}` : '')}</div>
      </div>
      {event.user_agent ? (
        <div>
          <div className={cx(s.label, s.mb2)}>User agent</div>
          <div className={s.pre}>{event.user_agent}</div>
        </div>
      ) : null}
      {event.body_truncated ? (
        <p className={cx(s.textXs, s.warningText)}>Request body was truncated during inspection.</p>
      ) : null}
      <div>
        <div className={cx(s.label, s.mb2)}>Matched rules</div>
        {event.matches.length === 0 ? (
          <p className={cx(s.textSm, s.textMuted)}>No rule metadata.</p>
        ) : (
          <div className={s.stackTight}>
            {event.matches.map((m, i) => (
              <div key={`${m.rule_id}-${i}`} className={s.matchRow}>
                <span className={s.mono}>{m.rule_id}</span>
                <span className={cx(s.textXs, s.textMuted)}>target: {m.target}</span>
                <SeverityBadge severity={m.severity ?? 'low'} />
                <ActionBadge action={m.action} />
                <span className={cx(s.textXs, s.textMuted)}>score {m.score}</span>
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
      <div className={cx(s.label, s.mb2)}>{label}</div>
      <div className={s.textSm}>{value}</div>
    </div>
  )
}
