package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestFixedWindow(t *testing.T) {
	now := time.Unix(0, 0)
	l := New([]Rule{{ID: "login", Paths: []string{"/login"}, Requests: 2, Window: 10}}, Config{})
	defer l.Stop()
	// Override the clock by passing explicit times.
	ip := netip.MustParseAddr("1.2.3.4")
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow(ip, "/login", now); !ok {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if ok, retry := l.Allow(ip, "/login", now); ok {
		t.Fatal("third request should be limited")
	} else if retry <= 0 {
		t.Fatalf("retry should be positive, got %v", retry)
	}
	// Next window resets.
	if ok, _ := l.Allow(ip, "/login", now.Add(11*time.Second)); !ok {
		t.Fatal("request in next window should be allowed")
	}
	// Other IPs unaffected.
	if ok, _ := l.Allow(netip.MustParseAddr("5.6.7.8"), "/login", now); !ok {
		t.Fatal("different IP should be allowed")
	}
}

func TestPathPatterns(t *testing.T) {
	l := New([]Rule{{ID: "api", Paths: []string{"/api/*"}, Requests: 1, Window: 60}}, Config{})
	defer l.Stop()
	ip := netip.MustParseAddr("1.1.1.1")
	now := time.Now()
	if ok, _ := l.Allow(ip, "/api/users", now); !ok {
		t.Fatal("first /api request should be allowed")
	}
	if ok, _ := l.Allow(ip, "/api/other", now); ok {
		t.Fatal("second /api request should be limited")
	}
	if ok, _ := l.Allow(ip, "/public", now); !ok {
		t.Fatal("non-matching path should be allowed")
	}
}

func TestNoRulesAlwaysAllow(t *testing.T) {
	l := New(nil, Config{})
	defer l.Stop()
	if ok, _ := l.Allow(netip.MustParseAddr("9.9.9.9"), "/", time.Now()); !ok {
		t.Fatal("no rules should allow")
	}
}

func TestBoundedEntries(t *testing.T) {
	l := New([]Rule{{ID: "all", Paths: []string{"*"}, Requests: 1, Window: 3600}}, Config{MaxEntries: 4, Cleanup: time.Hour})
	defer l.Stop()
	now := time.Now()
	for i := 0; i < 100; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		l.Allow(ip, "/", now)
	}
	if l.Len() > 4 {
		t.Fatalf("table exceeded bound: %d", l.Len())
	}
}

func TestCleanup(t *testing.T) {
	l := New([]Rule{{ID: "all", Paths: []string{"*"}, Requests: 1, Window: 1}}, Config{})
	defer l.Stop()
	now := time.Now()
	l.Allow(netip.MustParseAddr("1.1.1.1"), "/", now)
	l.cleanup(now.Add(2 * time.Second))
	if l.Len() != 0 {
		t.Fatalf("expected cleanup to remove entries, got %d", l.Len())
	}
}
