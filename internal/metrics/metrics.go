// Package metrics provides lock-free counters and a small Prometheus text
// exposition. It intentionally depends only on the standard library.
package metrics

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var durationBuckets = [...]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1}

// Metrics is a collection of process-wide counters. The zero value is ready
// for use.
type Metrics struct {
	RequestsTotal    atomic.Int64
	RequestsAllowed  atomic.Int64
	RequestsBlocked  atomic.Int64
	RuleMatchesTotal atomic.Int64
	RateLimitBlocked atomic.Int64
	EventsDropped    atomic.Int64
	EventsWritten    atomic.Int64
	RulesLoaded      atomic.Int64
	IPRulesLoaded    atomic.Int64

	durationSumNs atomic.Int64
	durationCount atomic.Int64
	buckets       [len(durationBuckets)]atomic.Int64
	timeline      timeline
}

// TimelinePoint is one hourly bucket of the rolling 24h chart.
type TimelinePoint struct {
	Hour     int64 `json:"hour"`
	Requests int64 `json:"requests"`
	Blocked  int64 `json:"blocked"`
}

type timeline struct {
	mu         sync.Mutex
	req        [24]atomic.Int64
	blocked    [24]atomic.Int64
	bucketHour [24]atomic.Int64
}

func (t *timeline) add(now time.Time, blocked bool) {
	h := now.Unix() / 3600
	idx := int(((h % 24) + 24) % 24)
	if t.bucketHour[idx].Load() != h {
		t.mu.Lock()
		if t.bucketHour[idx].Load() != h {
			t.req[idx].Store(0)
			t.blocked[idx].Store(0)
			t.bucketHour[idx].Store(h)
		}
		t.mu.Unlock()
	}
	t.req[idx].Add(1)
	if blocked {
		t.blocked[idx].Add(1)
	}
}

func (t *timeline) snapshot(now time.Time) []TimelinePoint {
	cur := now.Unix() / 3600
	out := make([]TimelinePoint, 0, 24)
	for i := int64(23); i >= 0; i-- {
		h := cur - i
		idx := int(((h % 24) + 24) % 24)
		p := TimelinePoint{Hour: h * 3600}
		if t.bucketHour[idx].Load() == h {
			p.Requests = t.req[idx].Load()
			p.Blocked = t.blocked[idx].Load()
		}
		out = append(out, p)
	}
	return out
}

// ObserveRequest records a request in the rolling traffic timeline.
func (m *Metrics) ObserveRequest(blocked bool) {
	m.timeline.add(time.Now(), blocked)
}

// Timeline returns the last 24 hourly buckets.
func (m *Metrics) Timeline() []TimelinePoint {
	return m.timeline.snapshot(time.Now())
}

// ObserveDuration records a WAF evaluation latency.
func (m *Metrics) ObserveDuration(seconds float64) {
	m.durationCount.Add(1)
	m.durationSumNs.Add(int64(seconds * 1e9))
	for i, b := range durationBuckets {
		if seconds <= b {
			m.buckets[i].Add(1)
		}
	}
}

// Prometheus renders the metrics in the text exposition format.
func (m *Metrics) Prometheus() string {
	var b strings.Builder
	counter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("sentra_requests_total", "Total requests evaluated by the WAF.", m.RequestsTotal.Load())
	counter("sentra_requests_allowed_total", "Requests allowed by the WAF.", m.RequestsAllowed.Load())
	counter("sentra_requests_blocked_total", "Requests blocked by the WAF.", m.RequestsBlocked.Load())
	counter("sentra_rule_matches_total", "Total rule matches.", m.RuleMatchesTotal.Load())
	counter("sentra_rate_limit_blocked_total", "Requests blocked by rate limiting.", m.RateLimitBlocked.Load())
	counter("sentra_events_dropped_total", "Security events dropped due to backpressure.", m.EventsDropped.Load())
	counter("sentra_events_written_total", "Security events persisted.", m.EventsWritten.Load())

	gauge := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	gauge("sentra_rules_loaded", "Number of enabled rules in the active ruleset.", m.RulesLoaded.Load())
	gauge("sentra_ip_rules_loaded", "Number of compiled IP rules.", m.IPRulesLoaded.Load())

	fmt.Fprintf(&b, "# HELP sentra_waf_duration_seconds WAF evaluation latency.\n# TYPE sentra_waf_duration_seconds histogram\n")
	var cumulative int64
	for i, ub := range durationBuckets {
		cumulative += m.buckets[i].Load()
		fmt.Fprintf(&b, "sentra_waf_duration_seconds_bucket{le=\"%s\"} %d\n", formatFloat(ub), cumulative)
	}
	fmt.Fprintf(&b, "sentra_waf_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.durationCount.Load())
	sum := float64(m.durationSumNs.Load()) / 1e9
	fmt.Fprintf(&b, "sentra_waf_duration_seconds_sum %s\n", formatFloat(sum))
	fmt.Fprintf(&b, "sentra_waf_duration_seconds_count %d\n", m.durationCount.Load())
	return b.String()
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// Snapshot is a JSON-friendly view for the dashboard API.
type Snapshot struct {
	RequestsTotal    int64           `json:"requests_total"`
	RequestsAllowed  int64           `json:"requests_allowed"`
	RequestsBlocked  int64           `json:"requests_blocked"`
	RuleMatchesTotal int64           `json:"rule_matches_total"`
	RateLimitBlocked int64           `json:"rate_limit_blocked"`
	EventsDropped    int64           `json:"events_dropped"`
	EventsWritten    int64           `json:"events_written"`
	RulesLoaded      int64           `json:"rules_loaded"`
	IPRulesLoaded    int64           `json:"ip_rules_loaded"`
	AvgDurationMS    float64         `json:"avg_waf_duration_ms"`
	Timeline         []TimelinePoint `json:"timeline,omitempty"`
}

// Snapshot returns a consistent-enough read of the counters.
func (m *Metrics) Snapshot() Snapshot {
	count := m.durationCount.Load()
	var avg float64
	if count > 0 {
		avg = float64(m.durationSumNs.Load()) / 1e9 / float64(count) * 1000
	}
	return Snapshot{
		RequestsTotal:    m.RequestsTotal.Load(),
		RequestsAllowed:  m.RequestsAllowed.Load(),
		RequestsBlocked:  m.RequestsBlocked.Load(),
		RuleMatchesTotal: m.RuleMatchesTotal.Load(),
		RateLimitBlocked: m.RateLimitBlocked.Load(),
		EventsDropped:    m.EventsDropped.Load(),
		EventsWritten:    m.EventsWritten.Load(),
		RulesLoaded:      m.RulesLoaded.Load(),
		IPRulesLoaded:    m.IPRulesLoaded.Load(),
		AvgDurationMS:    avg,
		Timeline:         m.Timeline(),
	}
}

// MetricNames is used by tests to assert the exposition is complete.
func MetricNames() []string {
	names := []string{
		"sentra_requests_total",
		"sentra_requests_allowed_total",
		"sentra_requests_blocked_total",
		"sentra_rule_matches_total",
		"sentra_rate_limit_blocked_total",
		"sentra_events_dropped_total",
		"sentra_events_written_total",
		"sentra_rules_loaded",
		"sentra_ip_rules_loaded",
		"sentra_waf_duration_seconds",
	}
	sort.Strings(names)
	return names
}
