# Sentra WAF — Design

Sentra is a lightweight, embeddable, self-hosted WAF. The core engine is fully
decoupled from Caddy; Caddy is one adapter among potentially several
(`net/http` middleware, standalone proxy may be added later).

```
                 control plane                     data plane
  React Admin ──► Management API ──► SQLite ──┐
                                              │ compile (off hot path)
                                              ▼
                                  atomic.Pointer[CompiledRuleset]
                                              │ load (lock-free)
                                              ▼
  client ──► Caddy adapter ──► WAF Engine ──► Decision ──► proxy
                                   │
                                   └──► SecurityEvent ──► buffered chan ──► EventWriter ──► SQLite
```

Hard rules:

* Request hot path performs **no** SQLite queries, **no** regexp compilation,
  and **no** mutex acquisition (except bounded rate-limit shards).
* Rulesets are immutable snapshots swapped with `atomic.Pointer`.
* A failed compile keeps the previous ruleset; a failed event write never
  affects traffic.
* Body inspection is lazy and bounded; if no rule needs a datum, it is never
  materialized.

---

## 1. Directory structure

```
sentra/
├── go.mod
├── sentra.go                     # root package; blank-imports caddy adapter
├── caddy/
│   ├── module.go                 # http.handlers.sentra, Provision/ServeHTTP
│   ├── caddyfile.go              # Caddyfile unmarshaler
│   ├── instance.go               # shared per-DB engine registry
│   └── module_test.go
├── cmd/
│   └── sentra/main.go            # optional standalone runner (management API)
├── internal/
│   ├── config/config.go          # Config struct + defaults
│   ├── rule/
│   │   ├── rule.go               # Rule model
│   │   ├── validate.go           # field validation
│   │   └── compiler.go           # -> CompiledRuleset
│   ├── matcher/
│   │   ├── matcher.go            # Matcher iface + Build()
│   │   └── matcher_test.go
│   ├── transform/
│   │   ├── transform.go          # registry + Pipeline
│   │   └── transform_test.go
│   ├── target/
│   │   ├── target.go             # Parse / Canonical key
│   │   └── target_test.go
│   ├── engine/
│   │   ├── engine.go             # Engine + Evaluate
│   │   ├── context.go            # RequestContext (lazy body/json)
│   │   ├── decision.go           # Decision / Match / Action
│   │   ├── ipresolve.go          # trusted-proxy client IP
│   │   ├── snapshot.go           # CompiledRuleset
│   │   └── *_test.go
│   ├── ipset/ipset.go            # binary prefix tries (allow/block)
│   ├── ratelimit/ratelimit.go    # bounded in-memory limiter
│   ├── event/event.go            # SecurityEvent + async Writer
│   ├── storage/
│   │   ├── storage.go            # interfaces
│   │   ├── sqlite.go             # database/sql impl
│   │   ├── migrations.go
│   │   └── sqlite_test.go
│   ├── metrics/metrics.go        # atomic counters + Prometheus text
│   ├── api/
│   │   ├── server.go             # routes, SPA serving, auth
│   │   ├── auth.go
│   │   ├── handlers_*.go
│   │   └── api_test.go
│   └── webassets/
│       ├── embed.go              # //go:embed all:dist
│       └── dist/index.html       # placeholder, replaced by web build
├── web/                          # React admin (Vite + TS)
│   ├── package.json
│   ├── vite.config.ts
│   ├── uno.config.ts
│   ├── src/
│   └── ...
├── testdata/
│   ├── attacks/*.txt
│   └── benign/*.txt
└── docs/DESIGN.md
```

A Go `embed` directive cannot reach the parent directory, so the built SPA is
copied to `internal/webassets/dist/` by the build script. A tracked
`dist/index.html` placeholder keeps `go build ./...` green before the frontend
is built.

---

## 2. Core Go types

### 2.1 Target

```go
type Kind uint8

const (
    KindMethod Kind = iota
    KindHost
    KindPath
    KindURI
    KindQuery
    KindBody
    KindHeader      // all header values
    KindCookie      // all cookie values
    KindQueryParam  // requires arg
    KindJSON        // requires arg
)

type Target struct {
    Kind Kind
    Arg  string // header/cookie/query_param name or json dotted path
}

func Parse(s string) (Target, error) // "header:User-Agent", "json:data.items.0.id"
func (t Target) String() string
func (t Target) Key() string // canonical grouping key
```

Naming semantics (explicit, documented in code):

| target | comparison |
| --- | --- |
| `method` | upper-cased, case-insensitive |
| `host` | lower-cased, port stripped |
| `path` | `URL.Path` (Go-decoded); use `url_decode` for double-encoding |
| `uri` | `URL.RequestURI()` (raw path + `?rawquery`) |
| `query` | raw query string |
| `body` | raw request body bytes (bounded) |
| `header` | every header value, including multi-value |
| `header:<name>` | `textproto.CanonicalMIMEHeaderKey`, case-insensitive |
| `cookie` | every cookie value |
| `cookie:<name>` | exact cookie name |
| `query_param:<name>` | raw (still encoded) value |
| `json:<dotted>` | dotted path, `a.b.0.c`; array index numeric |

A target without an argument that yields multiple values (`header`, `cookie`)
is expanded at runtime and the rule matches if any value matches.

### 2.2 Operator / Matcher

```go
type Matcher interface {
    Match(b []byte) bool
}
```

Operators: `regex`, `contains`, `equals`, `prefix`, `suffix`, `keyword_set`.
`ip_match` is reserved (IP handling lives in `ipset`). All regexes are compiled
once at ruleset build time with RE2.

### 2.3 Transform

```go
type Func func([]byte) []byte

type Transform struct {
    Name string
    Fn   Func
}
```

Registry: `lowercase`, `url_decode`, `html_decode`, `remove_nulls`,
`compress_whitespace`, `trim`. A `Pipeline` is an ordered list of `Func`
built from names.

### 2.4 Rule

```go
type Phase string   // "request" (only); "response" reserved

type Action string  // "allow" | "log" | "block"
type Severity string // "low" | "medium" | "high" | "critical"

type Rule struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Enabled     bool     `json:"enabled"`
    Phase       Phase    `json:"phase"`
    Targets     []string `json:"targets"`
    Operator    string   `json:"operator"`
    Value       string   `json:"value"`
    Values      []string `json:"values,omitempty"` // keyword_set
    Transforms  []string `json:"transforms"`
    Action      Action   `json:"action"`
    Score       int      `json:"score"`
    Severity    Severity `json:"severity"`
    Priority    int      `json:"priority"`
    Tags        []string `json:"tags"`
    Description string   `json:"description"`
}
```

### 2.5 Compiled ruleset (immutable)

```go
type CompiledRuleset struct {
    version    int64
    groups     []*TargetGroup // sorted by descending priority
    needBody   bool
    needJSON   bool
    needCookie bool
    ruleCount  int
}

type TargetGroup struct {
    Target     target.Target
    Pipeline   transform.Pipeline
    Matchers   []GroupMatcher
    priority   int
}

type GroupMatcher struct {
    Rule    *rule.Rule  // shared metadata
    Matcher matcher.Matcher
}
```

Grouping key = `target.Key() + "\x00" + strings.Join(transforms, ",")`. Within a
request each unique `(target, transforms)` pair is extracted/transformed
exactly once.

### 2.6 Decision

```go
type Decision struct {
    Action       Action   // allow | log | block
    StatusCode   int      // 403 for WAF block, 429 for rate limit, else 0
    Score        int
    Matches      []Match
    Blocked      bool
    RateLimited  bool
    BodyTruncated bool
    Debug        *DebugResult // only for playground
}

type Match struct {
    RuleID    string
    RuleName  string
    Target    string
    Severity  string
    Score     int
    Action    Action
    Raw       string // debug only
    Transformed string // debug only
}
```

`Raw`/`Transformed` are populated only in debug/playground evaluation; normal
security events keep match metadata only.

### 2.7 RequestContext

```go
type RequestContext struct {
    Method   string
    Scheme   string
    Host     string
    Path     string
    URI      string
    Query    string
    Headers  http.Header
    ClientIP netip.Addr

    // lazy
    bodyOnce      sync.Once
    body          []byte
    bodyTruncated bool
    bodyErr       error
    // json/form similarly
}
```

Constructed by `engine.NewRequestContext(r *http.Request, cfg)`. Body reading
buffers up to `maxBody`, then rewrites `r.Body` to
`MultiReader(bytes.NewReader(buf), remainder)` so the downstream proxy sees the
complete body. Avoids `sync.Once` cost on the hot path? `sync.Once` is cheap;
per-request allocation is the object itself.

### 2.8 Engine

```go
type Engine struct {
    cfg     Config
    rules   atomic.Pointer[rule.CompiledRuleset]
    ipset   atomic.Pointer[ipset.Set]
    limiter atomic.Pointer[ratelimit.Limiter]
    events  *event.Writer   // may be nil
    metrics *metrics.Metrics
}

func New(cfg Config) *Engine
func (e *Engine) ReloadRules(rules []rule.Rule) error       // compile + swap
func (e *Engine) ReloadIPRules(rules []ipset.Entry) error
func (e *Engine) Evaluate(ctx *RequestContext) Decision
func (e *Engine) EvaluateDebug(ctx *RequestContext) Decision // playground
```

---

## 3. Rule JSON schema

```json
{
  "id": "sqli-basic",
  "name": "Basic SQL Injection",
  "enabled": true,
  "phase": "request",
  "targets": ["query", "body"],
  "operator": "regex",
  "value": "(?i)union\\s+select",
  "transforms": ["url_decode", "remove_nulls", "compress_whitespace"],
  "action": "block",
  "score": 10,
  "severity": "high",
  "priority": 10,
  "tags": ["sqli"],
  "description": "Detect common UNION SELECT SQL injection"
}
```

Validation rules:

* `id` non-empty, matches `^[a-z0-9][a-z0-9._-]{1,63}$`, unique.
* `phase` must be `request` (others rejected with a clear message).
* `targets` non-empty, all parseable; arg-required targets must have an arg.
* `operator` known; `regex` compiles; `keyword_set` requires non-empty `values`.
* `transforms` all known.
* `action` ∈ {allow, block, log}; `score >= 0`; `severity` known.

---

## 4. SQLite schema

```sql
CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    phase       TEXT NOT NULL DEFAULT 'request',
    targets     TEXT NOT NULL,              -- JSON array
    operator    TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    values      TEXT NOT NULL DEFAULT '[]',
    transforms  TEXT NOT NULL DEFAULT '[]',
    action      TEXT NOT NULL DEFAULT 'block',
    score       INTEGER NOT NULL DEFAULT 0,
    severity    TEXT NOT NULL DEFAULT 'medium',
    priority    INTEGER NOT NULL DEFAULT 0,
    tags        TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    builtin     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE security_events (
    id             TEXT PRIMARY KEY,
    ts             INTEGER NOT NULL,
    client_ip      TEXT NOT NULL,
    method         TEXT NOT NULL,
    host           TEXT NOT NULL,
    path           TEXT NOT NULL,
    query          TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    status         INTEGER NOT NULL,
    score          INTEGER NOT NULL DEFAULT 0,
    duration_us    INTEGER NOT NULL DEFAULT 0,
    body_truncated INTEGER NOT NULL DEFAULT 0,
    user_agent     TEXT NOT NULL DEFAULT '',
    matches        TEXT NOT NULL DEFAULT '[]'  -- JSON
);
CREATE INDEX idx_events_ts     ON security_events(ts DESC);
CREATE INDEX idx_events_ip     ON security_events(client_ip);
CREATE INDEX idx_events_action ON security_events(action);

CREATE TABLE ip_rules (
    id         TEXT PRIMARY KEY,
    cidr       TEXT NOT NULL,
    action     TEXT NOT NULL,       -- allow | block
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,       -- JSON scalar/object
    updated_at TEXT NOT NULL
);
```

Migrations are forward-only, embedded in the binary, recorded in
`schema_migrations`. Driver: `modernc.org/sqlite` (pure Go, no cgo, plays nice
with `xcaddy` cross-builds). `database/sql`, no ORM.

---

## 5. Engine request lifecycle

```
ServeHTTP(w, r, next)
  1. Build RequestContext (cheap string/header copies; no body read)
  2. Resolve ClientIP
       remote := RemoteAddr
       if remote ∈ trusted_proxies:
           if client_ip_header set: use it
           else: rightmost XFF entry that is not trusted
       else: client = remote            // headers ignored
  3. snapshot := e.rules.Load()         // lock-free
  4. ipset: allow-match -> Decision{allow}, goto 8
             block-match -> Decision{block, 403}, goto 8
  5. ratelimit -> Decision{block, 429} if exceeded
  6. IF snapshot needs body/JSON: ctx.ensureBody(maxBody)   (lazy, bounded)
     FOR each group:
         values := extract(ctx, group.Target)               (lazy target)
         IF len(values)==0: continue
         transformed := group.Pipeline.Apply(values)        (once per group)
         FOR each matcher: if match -> append Match
         short-circuit when a block-action match is found
  7. aggregate score; if any block match OR score >= threshold -> block 403
  8. record metrics; if block/log -> enqueue SecurityEvent (non-blocking)
  9. return Decision to adapter
```

Key optimizations, all validated by benchmarks:

* unique pipelines only (grouping),
* no body read unless `snapshot.needBody`,
* no JSON parse unless `needJSON` and only on the targeted path,
* compiled matchers, no per-request allocation for the common case.

---

## 6. Hot reload & concurrency

```
admin API write ─► SQLite tx ─► rules = storage.ListRules()
                              ─► rule.Compile(rules)   // validate + compile
                                 ├─ error: return 4xx, old snapshot untouched
                                 └─ ok:   engine.rules.Store(newSnapshot)
```

* `atomic.Pointer[CompiledRuleset]` gives lock-free reads.
* Requests hold a pointer to their snapshot; in-flight requests finish on the
  old snapshot.
* The engine never mutates a live snapshot.
* IP rules and rate-limit config follow the same swap pattern.
* Rate limiter is internally sharded (fixed number of mutexes) and bounded.

Data plane vs control plane:

* Data plane: `engine.Evaluate`, ipset, rate limiter, metrics. No I/O.
* Control plane: storage, API, compiler, event writer. Failures isolated.
* Event writer uses a bounded channel; when full, events are dropped and
  `events_dropped` is incremented; the HTTP request is never blocked.

### Failure policy

| failure | behaviour |
| --- | --- |
| rule compile error | keep previous ruleset, return error to caller |
| SQLite event insert error | log, keep serving |
| SQLite unavailable at boot | Engine still runs with built-in default rules; admin API reports degraded |
| metrics failure | impossible (in-memory atomics) |
| admin API down | WAF unaffected |

---

## 7. Management API

`net/http` 1.22 pattern mux. All `/api/*` require `Authorization: Bearer <token>`
when a token is configured; otherwise the listener must be loopback. Static SPA
is served from embedded `webassets`. Routes:

```
GET    /api/dashboard
GET    /api/events?action=&ip=&rule=&path=&from=&to=&limit=&offset=
GET    /api/events/{id}
GET    /api/rules
POST   /api/rules
PUT    /api/rules/{id}
DELETE /api/rules/{id}
POST   /api/rules/test            # playground dry-run
GET    /api/ip-rules
POST   /api/ip-rules
DELETE /api/ip-rules/{id}
GET    /api/settings
PUT    /api/settings
GET    /api/metrics
GET    /metrics                   # Prometheus text (unauthenticated)
```

Rule writes: SQLite → compile → swap; on error return 400 and leave runtime
unchanged. Admin token is stored as SHA-256 and compared in constant time.

---

## 8. Default ruleset

Conservative, low false-positive rules covering SQLi, XSS, path traversal,
command injection, scanner UAs, sensitive files, Log4Shell JNDI, common probes.
Each ships with positive/negative cases under `testdata/{attacks,benign}` and a
Go test that runs the corpus against the engine.

---

## 9. Implementation phases

1. Rule model + validation
2. Matcher
3. Transform
4. Target parse/extract
5. Rule compiler
6. Engine + RequestContext + decision
7. Engine tests
8. Benchmarks
9. IP set
10. Rate limit
11. Event system
12. SQLite storage + migrations
13. Management API
14. Caddy adapter
15. React UI shell (tokens/router)
16. Playground
17. Default rules + corpus tests
18. Integration tests, race tests, docs

Gates after each phase: `go test ./...`, `go test -race ./...`; benchmarks once
the engine exists.

---

## 10. Risks & mitigations

| risk | mitigation |
| --- | --- |
| body read breaks downstream proxy | buffer prefix + `MultiReader`, never drain without restore |
| unbounded memory from random IPs | bounded rate-limit table with eviction, fail-open |
| forwarding-header spoofing | only honour headers from `trusted_proxies`, walk XFF right-to-left |
| regex DoS | RE2 has linear-time guarantees; reject patterns that fail to compile |
| large JSON parse cost | only parse when a JSON rule exists; dotted-path lookup |
| event backpressure | bounded channel + drop counter |
| admin exposure | loopback default + mandatory bearer token otherwise |
| `sync.Once` per lazy datum | zero-cost when unused; measured by benchmark |
| multiple Caddy handlers | shared engine instance keyed by DB path |
| SQLite driver weight | pure-Go `modernc.org/sqlite`, one dependency |
