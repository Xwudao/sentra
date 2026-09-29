export type Action = 'allow' | 'log' | 'block'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Operator = 'regex' | 'contains' | 'equals' | 'prefix' | 'suffix' | 'keyword_set'

export interface Rule {
  id: string
  name: string
  enabled: boolean
  phase: string
  targets: string[]
  operator: Operator
  value: string
  values?: string[]
  transforms: string[]
  action: Action
  score: number
  severity: Severity
  priority: number
  tags: string[]
  description: string
}

export interface Match {
  rule_id: string
  rule_name: string
  target: string
  severity?: string
  score: number
  action: Action
  raw_value?: string
  transformed_value?: string
}

export interface SecurityEvent {
  id: string
  timestamp: string
  client_ip: string
  method: string
  host: string
  path: string
  query?: string
  user_agent?: string
  action: string
  status: number
  score: number
  matches: Match[]
  duration_us: number
  body_truncated: boolean
}

export interface IPRule {
  id: string
  cidr: string
  action: 'allow' | 'block'
  note?: string
  created_at: string
}

export interface RateLimitRule {
  id: string
  paths: string[]
  requests: number
  window: number
}

export interface Settings {
  max_request_body_size: number
  body_limit_action: 'allow' | 'block'
  anomaly_threshold: number
  client_ip_header: string
  trusted_proxies?: string[]
  rate_limit: RateLimitRule[]
}

export interface TimelinePoint {
  hour: number
  requests: number
  blocked: number
}

export interface MetricsSnapshot {
  requests_total: number
  requests_allowed: number
  requests_blocked: number
  rule_matches_total: number
  rate_limit_blocked: number
  events_dropped: number
  events_written: number
  rules_loaded: number
  ip_rules_loaded: number
  avg_waf_duration_ms: number
  timeline?: TimelinePoint[]
}

export interface StatCount {
  key: string
  count: number
}

export interface Dashboard {
  version: string
  metrics: MetricsSnapshot
  events_total: number
  events_blocked: number
  top_ips: StatCount[]
  top_paths: StatCount[]
  top_rules: StatCount[]
}

export interface PlaygroundRequest {
  method: string
  url: string
  headers: Record<string, string>
  body: string
  client_ip: string
}

export interface PlaygroundResponse {
  action: Action
  score: number
  status: number
  blocked: boolean
  rate_limited: boolean
  body_truncated: boolean
  matches: Match[]
}
