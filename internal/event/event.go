// Package event defines security events and the bounded asynchronous writer
// that persists them. The writer must never block the request path.
package event

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/Xwudao/sentra/internal/metrics"
)

// Match is the persisted subset of a rule hit. Raw values are deliberately
// excluded: security events must not store sensitive request bodies.
type Match struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Target   string `json:"target"`
	Severity string `json:"severity,omitempty"`
	Score    int    `json:"score"`
	Action   string `json:"action"`
}

// SecurityEvent is the record produced when a request is blocked or logged.
type SecurityEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	Query         string    `json:"query,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Action        string    `json:"action"`
	Status        int       `json:"status"`
	Score         int       `json:"score"`
	Matches       []Match   `json:"matches"`
	DurationUS    int64     `json:"duration_us"`
	BodyTruncated bool      `json:"body_truncated"`
}

// Store persists batches of events.
type Store interface {
	InsertEvents(ctx context.Context, events []SecurityEvent) error
}

// WriterConfig tunes the asynchronous writer.
type WriterConfig struct {
	QueueSize  int
	BatchSize  int
	FlushEvery time.Duration
	WriteWait  time.Duration
}

func (c WriterConfig) withDefaults() WriterConfig {
	if c.QueueSize <= 0 {
		c.QueueSize = 4096
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 128
	}
	if c.FlushEvery <= 0 {
		c.FlushEvery = time.Second
	}
	if c.WriteWait <= 0 {
		c.WriteWait = 5 * time.Second
	}
	return c
}

// Writer consumes events from a bounded channel and writes them in batches.
type Writer struct {
	ch      chan SecurityEvent
	store   Store
	metrics *metrics.Metrics
	logger  *slog.Logger
	cfg     WriterConfig

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewWriter starts a writer goroutine. store may be nil, in which case events
// are discarded (useful for tests and rule-only deployments).
func NewWriter(store Store, m *metrics.Metrics, logger *slog.Logger, cfg WriterConfig) *Writer {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	w := &Writer{
		ch:      make(chan SecurityEvent, cfg.QueueSize),
		store:   store,
		metrics: m,
		logger:  logger,
		cfg:     cfg,
		done:    make(chan struct{}),
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Emit enqueues an event. It never blocks: if the queue is full the event is
// dropped and counted.
func (w *Writer) Emit(e SecurityEvent) {
	if w == nil {
		return
	}
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	select {
	case w.ch <- e:
	default:
		if w.metrics != nil {
			w.metrics.EventsDropped.Add(1)
		}
	}
}

// Dropped reports the current queue depth (for diagnostics).
func (w *Writer) QueueLen() int { return len(w.ch) }

// Close drains pending events and stops the writer.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		close(w.done)
		w.wg.Wait()
	})
}

func (w *Writer) run() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.cfg.FlushEvery)
	defer ticker.Stop()

	buf := make([]SecurityEvent, 0, w.cfg.BatchSize)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		w.persist(buf)
		buf = buf[:0]
	}
	for {
		select {
		case <-w.done:
			// Drain whatever remains without blocking shutdown for long.
			for {
				select {
				case e := <-w.ch:
					buf = append(buf, e)
					if len(buf) >= w.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case e := <-w.ch:
			buf = append(buf, e)
			if len(buf) >= w.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *Writer) persist(batch []SecurityEvent) {
	if w.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.WriteWait)
	defer cancel()
	if err := w.store.InsertEvents(ctx, batch); err != nil {
		w.logger.Error("failed to persist security events", "count", len(batch), "error", err)
		return
	}
	if w.metrics != nil {
		w.metrics.EventsWritten.Add(int64(len(batch)))
	}
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
