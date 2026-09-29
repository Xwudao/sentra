import type { StatCount, TimelinePoint } from '@/lib/types'
import { formatHour, formatNumber } from '@/lib/format'
import { EmptyState } from './ui'
import s from './chart.module.scss'

export function TrafficChart({ data }: { data: TimelinePoint[] }) {
  if (!data || data.length === 0)
    return <EmptyState icon="i-lucide-chart-no-axes-column" title="No traffic recorded" description="Request volume will appear here once the engine handles traffic." />
  const max = Math.max(1, ...data.map((d) => d.requests))
  const width = 720
  const height = 180
  const barGap = 4
  const barWidth = (width - barGap * (data.length - 1)) / data.length

  return (
    <div className={s.chart}>
      <svg viewBox={`0 0 ${width} ${height + 26}`} width="100%" height="220" role="img" aria-label="Requests over the last 24 hours">
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <line
            key={f}
            x1={0}
            x2={width}
            y1={height - height * f}
            y2={height - height * f}
            stroke="var(--border)"
            strokeDasharray="3 4"
          />
        ))}
        {data.map((d, i) => {
          const x = i * (barWidth + barGap)
          const total = (d.requests / max) * height
          const blocked = (d.blocked / max) * height
          return (
            <g key={d.hour}>
              <title>{`${formatHour(d.hour)} · ${d.requests} requests · ${d.blocked} blocked`}</title>
              <rect x={x} y={height - total} width={barWidth} height={total} rx={2} fill="var(--accent-soft)" />
              <rect x={x} y={height - blocked} width={barWidth} height={blocked} rx={2} fill="var(--danger)" />
              {i % 4 === 0 ? (
                <text x={x + barWidth / 2} y={height + 18} textAnchor="middle" fontSize="10" fill="var(--text-muted)">
                  {formatHour(d.hour)}
                </text>
              ) : null}
            </g>
          )
        })}
      </svg>
      <div className={s.legend}>
        <span className={s.legendItem}>
          <span className={s.swatchRequests} /> Requests
        </span>
        <span className={s.legendItem}>
          <span className={s.swatchBlocked} /> Blocked
        </span>
      </div>
    </div>
  )
}

export function TopList({ items, empty }: { items: StatCount[]; empty: string }) {
  if (!items || items.length === 0) return <EmptyState icon="i-lucide-inbox" title={empty} />
  const max = Math.max(1, ...items.map((i) => i.count))
  return (
    <div className={s.topList}>
      {items.map((item) => (
        <div key={item.key} className={s.topItem}>
          <div className={s.topItemBody}>
            <div className={s.topItemMeta}>
              <span className={s.topItemKey} title={item.key}>
                {item.key}
              </span>
              <span className={s.topItemCount}>{formatNumber(item.count)}</span>
            </div>
            <div className={s.track}>
              <div className={s.fill} style={{ width: `${(item.count / max) * 100}%` }} />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
