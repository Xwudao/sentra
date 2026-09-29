import { TrafficChart, TopList } from '@/components/Chart'
import { Card, CardHeader, PageHeader, Spinner, StatCard } from '@/components/ui'
import { useApiQuery } from '@/lib/api'
import { formatDuration, formatNumber } from '@/lib/format'
import type { Dashboard } from '@/lib/types'

export function OverviewPage() {
  const { data, loading, error } = useApiQuery<Dashboard>('/api/dashboard')

  if (loading && !data) return <Spinner label="Loading dashboard" />
  if (error) return <Card>Failed to load dashboard: {error.message}</Card>
  if (!data) return null

  const m = data.metrics
  const blockRate = m.requests_total > 0 ? (m.requests_blocked / m.requests_total) * 100 : 0

  return (
    <>
      <PageHeader title="Overview" description={`Sentra ${data.version} · live traffic and detection summary`} />

      <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(11rem, 1fr))' }}>
        <StatCard label="Requests" value={formatNumber(m.requests_total)} />
        <StatCard label="Blocked" value={formatNumber(m.requests_blocked)} tone="danger" />
        <StatCard label="Block rate" value={`${blockRate.toFixed(1)}%`} tone={blockRate > 5 ? 'danger' : 'success'} />
        <StatCard label="Avg WAF latency" value={formatDuration(m.avg_waf_duration_ms)} tone="accent" />
      </div>

      <div className="grid gap-4 mb-6">
        <Card>
          <CardHeader title="Traffic · last 24 hours" subtitle="Request volume with blocked overlay" />
          <TrafficChart data={m.timeline ?? []} />
        </Card>
      </div>

      <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(18rem, 1fr))' }}>
        <Card>
          <CardHeader title="Top rules" subtitle="Most frequently matched rules (24h)" />
          <TopList items={data.top_rules} empty="No rule matches recorded yet." />
        </Card>
        <Card>
          <CardHeader title="Top source IPs" subtitle="By blocked/logged events (24h)" />
          <TopList items={data.top_ips} empty="No source IPs recorded yet." />
        </Card>
        <Card>
          <CardHeader title="Top paths" subtitle="Most targeted paths (24h)" />
          <TopList items={data.top_paths} empty="No paths recorded yet." />
        </Card>
      </div>
    </>
  )
}
