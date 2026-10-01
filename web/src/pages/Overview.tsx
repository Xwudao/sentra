import { TrafficChart, TopList } from '@/components/Chart'
import { Button, Card, CardHeader, PageHeader, Spinner, StatCard, cx } from '@/components/ui'
import s from '@/components/ui.module.scss'
import { useApiQuery } from '@/lib/api'
import { formatDuration, formatNumber } from '@/lib/format'
import type { Dashboard } from '@/lib/types'

type EventSummary = Pick<Dashboard, 'top_ips' | 'top_paths' | 'top_rules'>

export function OverviewPage() {
  const { data, loading, error } = useApiQuery<Dashboard>('/api/dashboard')
  const { data: summary, loading: summaryLoading, error: summaryError, reload: reloadSummary } = useApiQuery<EventSummary>('/api/dashboard/events')

  if (loading && !data) return <Spinner label="Loading dashboard" />
  if (error) return <Card>Failed to load dashboard: {error.message}</Card>
  if (!data) return null

  const m = data.metrics
  const blockRate = m.requests_total > 0 ? (m.requests_blocked / m.requests_total) * 100 : 0

  return (
    <>
      <PageHeader title="Overview" description={`Sentra ${data.version} · live traffic and detection summary`} />

      <div className={cx(s.statGrid, s.mb6)}>
        <StatCard label="Requests" value={formatNumber(m.requests_total)} icon="i-lucide-activity" hint="Last 24 hours" />
        <StatCard label="Blocked" value={formatNumber(m.requests_blocked)} tone="danger" icon="i-lucide-shield-x" hint="Denied by the ruleset" />
        <StatCard
          label="Block rate"
          value={`${blockRate.toFixed(1)}%`}
          tone={blockRate > 5 ? 'danger' : 'success'}
          icon="i-lucide-percent"
          hint="Share of blocked requests"
        />
        <StatCard label="Avg WAF latency" value={formatDuration(m.avg_waf_duration_ms)} tone="accent" icon="i-lucide-timer" hint="Per-request inspection" />
      </div>

      <div className={cx(s.grid, s.mb6)}>
        <Card>
          <CardHeader title="Traffic · last 24 hours" subtitle="Request volume with blocked overlay" />
          <TrafficChart data={m.timeline ?? []} />
        </Card>
      </div>

      {summaryError ? (
        <Card className={s.mb4}>
          Event summary is unavailable (the database may be busy). <Button size="sm" onClick={reloadSummary}>Retry</Button>
        </Card>
      ) : null}
      <div className={s.grid} style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(18rem, 1fr))' }}>
        <Card>
          <CardHeader title="Top rules" subtitle="Most frequently matched rules (24h)" />
          <TopList items={summary?.top_rules ?? []} empty={summaryLoading ? 'Loading event summary…' : 'No rule matches recorded yet.'} />
        </Card>
        <Card>
          <CardHeader title="Top source IPs" subtitle="By blocked/logged events (24h)" />
          <TopList items={summary?.top_ips ?? []} empty={summaryLoading ? 'Loading event summary…' : 'No source IPs recorded yet.'} />
        </Card>
        <Card>
          <CardHeader title="Top paths" subtitle="Most targeted paths (24h)" />
          <TopList items={summary?.top_paths ?? []} empty={summaryLoading ? 'Loading event summary…' : 'No paths recorded yet.'} />
        </Card>
      </div>
    </>
  )
}
