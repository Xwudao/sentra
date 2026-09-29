# Sentra WAF

Sentra is a lightweight, high-performance, self-hosted Web Application Firewall
written in Go with a React admin UI. It is designed to be embedded in Caddy
(via a Caddy v2 module) while keeping the core WAF engine completely
independent from Caddy.

It is **not** a ModSecurity / OWASP CRS replacement. It aims to be a small,
reliable WAF that is actually pleasant to deploy and maintain, with rules that
are easy to write and audit.

## Highlights

- **Caddy-free engine.** `internal/engine` has no Caddy dependency. Caddy,
  `net/http` and the standalone proxy are thin adapters.
- **Compiled execution plan.** Rules are grouped by `(target, transforms)` and
  compiled once; the request path extracts and transforms each unique pipeline
  exactly once. Regexes are compiled at load time, never per request.
- **Lock-free hot reload.** Rulesets are immutable snapshots swapped with
  `atomic.Pointer`. A bad ruleset never takes the WAF down; the previous one
  stays active.
- **Lazy, bounded inspection.** Request bodies and JSON are only read when a
  rule needs them, and only up to a configured window. Downstream still sees the
  full body.
- **Bounded everything.** Bounded body reads, bounded event queue, bounded
  rate-limit table, bounded in-memory state.
- **Data plane / control plane split.** Events are written asynchronously in
  batches; SQLite is never touched on the request path.
- **Management API + UI.** Rules, IP rules, rate limits, settings, events and a
  rule playground, served from an embedded SPA.
- **Conservative default ruleset.** SQLi, XSS, path traversal, command
  injection, scanner UAs, sensitive files, Log4Shell, common probes — with a
  positive/negative corpus test.

## Repository layout

```
internal/engine      request context, evaluation, decisions, IP resolution
internal/rule        rule model, validation, compiler (execution plan)
internal/matcher     compiled operators (regex, contains, ...)
internal/transform   normalisation pipeline
internal/target      target parsing/extraction keys
internal/ipset       binary prefix tries for allow/block
internal/ratelimit   bounded sharded fixed-window limiter
internal/event       security events + async batch writer
internal/storage     SQLite persistence + migrations
internal/api         management REST API + SPA serving
internal/metrics     counters + Prometheus exposition
internal/defaults    built-in ruleset + seeding
internal/webassets   embedded React build
caddy/               Caddy v2 http handler adapter
cmd/sentra           standalone reverse-proxy binary
web/                 React + TypeScript admin UI
docs/DESIGN.md       full design document
```

## Build

Requires Go 1.25+ and pnpm.

```bash
# Build the SPA, embed it, and compile everything.
make

# Run tests
go test ./...
go test -race ./...

# Benchmarks
make bench
```

## Use with Caddy

```bash
xcaddy build --with github.com/Xwudao/sentra
```

```caddyfile
example.com {
    route {
        sentra {
            db /var/lib/sentra/sentra.db
            max_request_body_size 2MB
            anomaly_threshold 10

            trusted_proxies private_ranges
            client_ip_header CF-Connecting-IP

            admin_listen 127.0.0.1:2020
            admin_token {env.SENTRA_ADMIN_TOKEN}
        }

        reverse_proxy localhost:8080
    }
}
```

Open the admin UI at `http://127.0.0.1:2020`. When no `admin_token` is set the
management API only accepts loopback connections; set one before exposing the
listener.

## Standalone

```bash
go run ./cmd/sentra \
  -db sentra.db \
  -listen 127.0.0.1:8080 \
  -upstream http://127.0.0.1:3000 \
  -admin 127.0.0.1:2020 \
  -admin-token "$SENTRA_ADMIN_TOKEN"
```

## Rule format

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
  "priority": 100,
  "tags": ["sqli"],
  "description": "Detect common UNION SELECT SQL injection"
}
```

- **Targets**: `method`, `host`, `path`, `uri`, `query`, `body`,
  `header`, `header:<name>`, `cookie`, `cookie:<name>`, `query_param:<name>`,
  `json:<dotted.path>`.
- **Operators**: `regex` (RE2), `contains`, `equals`, `prefix`, `suffix`,
  `keyword_set`.
- **Transforms**: `lowercase`, `url_decode`, `html_decode`, `remove_nulls`,
  `compress_whitespace`, `trim`.
- **Actions**: `block`, `log`, `allow` (whitelist).
- **Anomaly scoring**: `log` rules accumulate `score`; when the total reaches
  `anomaly_threshold` the request is blocked.

## Security model

Forwarding headers (`X-Forwarded-For`, a configured client IP header) are only
trusted when the direct peer is inside `trusted_proxies`. Otherwise the direct
peer address is used, and spoofed headers are ignored.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture, SQLite schema,
concurrency model and failure policy.

## License

MIT
