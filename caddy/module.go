package caddymod

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/Xwudao/sentra/internal/engine"
)

// Version is stamped at build time.
var Version = "dev"

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("sentra", parseCaddyfile)
}

// Handler is the `sentra` Caddy HTTP handler.
type Handler struct {
	// DB is the SQLite database path. Defaults to <caddy data dir>/sentra/sentra.db.
	DB string `json:"db,omitempty"`
	// MaxRequestBodySize is the body inspection window in bytes. Accepts
	// Caddyfile sizes such as 2MB.
	MaxRequestBodySize int64 `json:"max_request_body_size,omitempty"`
	// BodyLimitAction is "allow" or "block" when the body exceeds the window.
	BodyLimitAction string `json:"body_limit_action,omitempty"`
	// AnomalyThreshold blocks once accumulated rule score reaches this value.
	AnomalyThreshold int `json:"anomaly_threshold,omitempty"`
	// TrustedProxies lists CIDRs whose forwarding headers are honoured.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	// ClientIPHeader is the header carrying the real client IP (e.g.
	// CF-Connecting-IP), only trusted from TrustedProxies.
	ClientIPHeader string `json:"client_ip_header,omitempty"`
	// AdminListen is the management API listen address. "off" disables it.
	AdminListen string `json:"admin_listen,omitempty"`
	// AdminToken protects the management API with bearer auth.
	AdminToken string `json:"admin_token,omitempty"`

	inst *instance
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.sentra",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision opens the shared engine for this handler's database.
func (h *Handler) Provision(ctx caddy.Context) error {
	cfg, err := h.config()
	if err != nil {
		return err
	}
	inst, err := acquire(cfg)
	if err != nil {
		return err
	}
	h.inst = inst
	return nil
}

// Validate validates the handler configuration.
func (h *Handler) Validate() error {
	if h.BodyLimitAction != "" && h.BodyLimitAction != "allow" && h.BodyLimitAction != "block" {
		return fmt.Errorf("body_limit_action must be allow or block")
	}
	_, err := h.config()
	return err
}

// Cleanup releases the shared engine when the last handler goes away.
func (h *Handler) Cleanup() error {
	release(h.inst)
	h.inst = nil
	return nil
}

// ServeHTTP evaluates the request and either blocks or forwards it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.inst == nil {
		return next.ServeHTTP(w, r)
	}
	rc := h.inst.engine.NewContext(r)
	d := h.inst.engine.Evaluate(rc)
	if d.Blocked {
		status := d.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Sentra-Action", "blocked")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(http.StatusText(status) + "\n"))
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) config() (handlerConfig, error) {
	proxies, err := parsePrefixes(h.TrustedProxies)
	if err != nil {
		return handlerConfig{}, err
	}
	cfg := handlerConfig{
		dbPath:             h.DB,
		maxRequestBodySize: h.MaxRequestBodySize,
		bodyLimitAction:    engine.BodyLimitAction(h.BodyLimitAction),
		anomalyThreshold:   h.AnomalyThreshold,
		trustedProxies:     proxies,
		clientIPHeader:     h.ClientIPHeader,
		adminListen:        h.AdminListen,
		adminToken:         h.AdminToken,
		version:            Version,
	}
	return cfg, nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &handler, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "db":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.DB = d.Val()
		case "max_request_body_size":
			if !d.NextArg() {
				return d.ArgErr()
			}
			size, err := parseSize(d.Val())
			if err != nil {
				return d.Errf("invalid max_request_body_size: %v", err)
			}
			h.MaxRequestBodySize = size
		case "body_limit_action":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.BodyLimitAction = d.Val()
		case "anomaly_threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid anomaly_threshold: %v", err)
			}
			h.AnomalyThreshold = n
		case "trusted_proxies":
			if !d.NextArg() {
				return d.ArgErr()
			}
			for {
				h.TrustedProxies = append(h.TrustedProxies, expandProxyToken(d.Val())...)
				if !d.NextArg() {
					break
				}
			}
		case "client_ip_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ClientIPHeader = d.Val()
		case "admin_listen":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.AdminListen = d.Val()
		case "admin_token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.AdminToken = d.Val()
		default:
			return d.Errf("unrecognized sentra option %q", d.Val())
		}
	}
	return nil
}

// privateRanges is the expansion of the `private_ranges` shorthand.
var privateRanges = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

func expandProxyToken(tok string) []string {
	if tok == "private_ranges" {
		return privateRanges
	}
	return []string{tok}
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("invalid trusted proxy %q", s)
	}
	return out, nil
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "KIB"):
		mult, s = 1024, strings.TrimSuffix(s, "KIB")
	case strings.HasSuffix(s, "MIB"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "MIB")
	case strings.HasSuffix(s, "GIB"):
		mult, s = 1024*1024*1024, strings.TrimSuffix(s, "GIB")
	case strings.HasSuffix(s, "KB"):
		mult, s = 1000, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1000*1000, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		mult, s = 1000*1000*1000, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "B"):
		mult, s = 1, strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return int64(n * float64(mult)), nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
