import type { StatCount, TimelinePoint } from '@/lib/types'
import { formatHour, formatNumber } from '@/lib/format'
import { EmptyState } from './ui'

export function TrafficChart({ data }: { data: TimelinePoint[] }) {
  if (!data || data.length === 0) return <EmptyState>No traffic recorded yet.</EmptyState>
  const max = Math.max(1, ...data.map((d) => d.requests))
  const width = 720
  const height = 180
  const barGap = 4
  const barWidth = (width - barGap * (data.length - 1)) / data.length

  return (
    <div style={{ width: '100%' }}>
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
      <div className="flex items-center gap-4 text-xs text-[var(--text-muted)] mt-1">
        <span className="flex items-center gap-1">
          <span className="inline-block w-2.5 h-2.5 rounded-sm bg-[var(--accent-soft)]" /> Requests
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block w-2.5 h-2.5 rounded-sm bg-[var(--danger)]" /> Blocked
        </span>
      </div>
    </div>
  )
}

export function TopList({ items, empty }: { items: StatCount[]; empty: string }) {
  if (!items || items.length === 0) return <EmptyState>{empty}</EmptyState>
  const max = Math.max(1, ...items.map((i) => i.count))
  return (
    <div className="flex flex-col gap-2">
      {items.map((item) => (
        <div key={item.key} className="flex items-center gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-xs font-mono truncate" title={item.key}>
                {item.key}
              </span>
              <span className="text-xs text-[var(--text-muted)]">{formatNumber(item.count)}</span>
            </div>
            <div className="h-1.5 rounded-full bg-[var(--surface-muted)] overflow-hidden">
              <div className="h-full rounded-full bg-[var(--accent)]" style={{ width: `${(item.count / max) * 100}%` }} />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
