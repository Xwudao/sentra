package engine

import (
	"net/http"
	"net/netip"
	"strings"
)

// ResolveClientIP determines the effective client address.
//
// Forwarding headers are only consulted when the immediate peer is a trusted
// proxy. This prevents a client from spoofing its address by sending
// X-Forwarded-For or CF-Connecting-IP directly.
func ResolveClientIP(r *http.Request, trusted []netip.Prefix, header string) netip.Addr {
	remote := ParseAddr(r.RemoteAddr)
	if len(trusted) == 0 || !inPrefixes(remote, trusted) {
		return remote
	}
	if header != "" {
		if a := firstValidAddr(r.Header.Get(header)); a.IsValid() {
			return a
		}
	}
	// Walk X-Forwarded-For right-to-left, skipping trusted proxies.
	var parts []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		parts = append(parts, strings.Split(v, ",")...)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		a := ParseAddr(parts[i])
		if !a.IsValid() {
			continue
		}
		if inPrefixes(a, trusted) {
			continue
		}
		return a
	}
	return remote
}

// ParseAddr parses a host or host:port into a netip.Addr.
func ParseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr()
	}
	// Hostnames are not resolvable here; callers get an invalid address.
	return netip.Addr{}
}

// firstValidAddr returns the first parseable address in a possibly
// comma-separated header value.
func firstValidAddr(value string) netip.Addr {
	for _, part := range strings.Split(value, ",") {
		if a := ParseAddr(part); a.IsValid() {
			return a
		}
	}
	return netip.Addr{}
}

func inPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
