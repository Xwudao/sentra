package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/Xwudao/sentra/internal/target"
)

// defaultMaxBody is used when the configured limit is unset or non-positive.
const defaultMaxBody = 2 << 20 // 2 MiB

// RequestContext is the normalised view of an incoming request. Expensive
// members (body, JSON) are materialised lazily and at most once.
type RequestContext struct {
	Method   string
	Scheme   string
	Host     string
	Path     string
	URI      string
	Query    string
	Headers  http.Header
	ClientIP netip.Addr

	req     *http.Request
	maxBody int64

	bodyOnce      sync.Once
	body          []byte
	bodyTruncated bool
	bodyErr       error

	jsonOnce sync.Once
	jsonVal  any
	jsonErr  error

	cookieOnce sync.Once
	cookies    []*http.Cookie
}

// NewRequestContext builds a context from a net/http request. No body bytes
// are read here.
func NewRequestContext(r *http.Request, maxBody int64) *RequestContext {
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	uri := r.URL.RequestURI()
	return &RequestContext{
		Method:  r.Method,
		Scheme:  schemeOf(r),
		Host:    host,
		Path:    r.URL.Path,
		URI:     uri,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		req:     r,
		maxBody: maxBody,
	}
}

func schemeOf(r *http.Request) string {
	if r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// BodyTruncated reports whether the inspected body exceeded the limit. It is
// only meaningful after extraction has run.
func (c *RequestContext) BodyTruncated() bool { return c.bodyTruncated }

// Body returns the (bounded) body bytes, reading them if necessary.
func (c *RequestContext) Body() []byte {
	c.ensureBody()
	return c.body
}

// Request exposes the underlying request so adapters can restore/drain it.
func (c *RequestContext) Request() *http.Request { return c.req }

func (c *RequestContext) ensureBody() {
	c.bodyOnce.Do(func() {
		if c.req == nil || c.req.Body == nil {
			return
		}
		limit := c.maxBody
		if limit <= 0 {
			limit = defaultMaxBody
		}
		data, err := io.ReadAll(io.LimitReader(c.req.Body, limit+1))
		truncated := int64(len(data)) > limit
		c.body = data
		if truncated {
			c.body = data[:limit]
		}
		c.bodyTruncated = truncated

		// Restore the full stream so the downstream proxy can still read the
		// complete body, including bytes beyond the inspection window.
		orig := c.req.Body
		c.req.Body = &prefixReadCloser{prefix: bytes.NewReader(data), rest: orig}
		if c.req.GetBody == nil && err == nil {
			snapshot := append([]byte(nil), data...)
			c.req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(snapshot)), nil
			}
		}
		c.bodyErr = err
	})
}

// BodyErr returns any error encountered while reading the body.
func (c *RequestContext) BodyErr() error { return c.bodyErr }

func (c *RequestContext) ensureJSON() {
	c.jsonOnce.Do(func() {
		c.ensureBody()
		if len(c.body) == 0 {
			return
		}
		dec := json.NewDecoder(bytes.NewReader(c.body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			c.jsonErr = err
			return
		}
		c.jsonVal = v
	})
}

func (c *RequestContext) ensureCookies() {
	c.cookieOnce.Do(func() {
		if c.req == nil {
			return
		}
		c.cookies = c.req.Cookies()
	})
}

// Extract returns every value the target resolves to. A nil/empty result
// means the datum is absent. Header and cookie targets without an argument
// expand to all values.
func (c *RequestContext) Extract(t target.Target) [][]byte {
	switch t.Kind {
	case target.KindMethod:
		return one(c.Method)
	case target.KindHost:
		return one(c.Host)
	case target.KindPath:
		return one(c.Path)
	case target.KindURI:
		return one(c.URI)
	case target.KindQuery:
		if c.Query == "" {
			return nil
		}
		return one(c.Query)
	case target.KindBody:
		c.ensureBody()
		if len(c.body) == 0 {
			return nil
		}
		return oneBytes(c.body)
	case target.KindHeader:
		return c.extractHeader(t.Arg)
	case target.KindCookie:
		return c.extractCookie(t.Arg)
	case target.KindQueryParam:
		return c.extractQueryParam(t.Arg)
	case target.KindJSON:
		return c.extractJSON(t.Arg)
	}
	return nil
}

func (c *RequestContext) extractHeader(name string) [][]byte {
	if name == "" {
		if len(c.Headers) == 0 {
			return nil
		}
		var out [][]byte
		for _, vs := range c.Headers {
			for _, v := range vs {
				out = append(out, []byte(v))
			}
		}
		return out
	}
	vs := c.Headers.Values(name)
	if len(vs) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(vs))
	for _, v := range vs {
		out = append(out, []byte(v))
	}
	return out
}

func (c *RequestContext) extractCookie(name string) [][]byte {
	c.ensureCookies()
	if len(c.cookies) == 0 {
		return nil
	}
	if name == "" {
		out := make([][]byte, 0, len(c.cookies))
		for _, ck := range c.cookies {
			out = append(out, []byte(ck.Value))
		}
		return out
	}
	var out [][]byte
	for _, ck := range c.cookies {
		if strings.EqualFold(ck.Name, name) {
			out = append(out, []byte(ck.Value))
		}
	}
	return out
}

func (c *RequestContext) extractQueryParam(name string) [][]byte {
	if c.Query == "" {
		return nil
	}
	var out [][]byte
	for _, pair := range strings.Split(c.Query, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if queryKeyEqual(k, name) {
			out = append(out, []byte(v))
		}
	}
	return out
}

func queryKeyEqual(raw, want string) bool {
	if raw == want {
		return true
	}
	if dec, err := url.QueryUnescape(raw); err == nil {
		return dec == want
	}
	return false
}

func (c *RequestContext) extractJSON(path string) [][]byte {
	c.ensureJSON()
	if c.jsonVal == nil {
		return nil
	}
	segments := strings.Split(path, ".")
	cur := c.jsonVal
	for _, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil
			}
			cur = node[idx]
		default:
			return nil
		}
	}
	return oneBytes(jsonScalar(cur))
}

func jsonScalar(v any) []byte {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []byte(x)
	case json.Number:
		return []byte(x.String())
	case bool:
		if x {
			return []byte("true")
		}
		return []byte("false")
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return nil
		}
		return b
	}
}

func one(s string) [][]byte {
	if s == "" {
		return nil
	}
	return [][]byte{[]byte(s)}
}

func oneBytes(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	return [][]byte{b}
}

type prefixReadCloser struct {
	prefix *bytes.Reader
	rest   io.ReadCloser
}

func (p *prefixReadCloser) Read(b []byte) (int, error) {
	if p.prefix.Len() > 0 {
		return p.prefix.Read(b)
	}
	return p.rest.Read(b)
}

func (p *prefixReadCloser) Close() error { return p.rest.Close() }
