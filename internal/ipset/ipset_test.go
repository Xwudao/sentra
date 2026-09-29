package ipset

import (
	"net/netip"
	"testing"
)

func mustPrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func TestBuildAndLookup(t *testing.T) {
	set, err := Build([]Entry{
		{ID: "allow-corp", Prefix: mustPrefix("10.0.0.0/8"), Action: ActionAllow},
		{ID: "block-bad", Prefix: mustPrefix("203.0.113.0/24"), Action: ActionBlock},
		{ID: "block-v6", Prefix: mustPrefix("2001:db8::/32"), Action: ActionBlock},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip     string
		action Action
		ok     bool
	}{
		{"10.1.2.3", ActionAllow, true},
		{"203.0.113.9", ActionBlock, true},
		{"203.0.114.9", 0, false},
		{"2001:db8::1", ActionBlock, true},
		{"2001:dead::1", 0, false},
		{"8.8.8.8", 0, false},
	}
	for _, c := range cases {
		a, ok := set.ActionFor(netip.MustParseAddr(c.ip))
		if ok != c.ok || (ok && a != c.action) {
			t.Errorf("ActionFor(%s)=(%v,%v) want (%v,%v)", c.ip, a, ok, c.action, c.ok)
		}
	}
	if set.Size() != 3 {
		t.Errorf("Size=%d want 3", set.Size())
	}
}

func TestAllowWins(t *testing.T) {
	set, err := Build([]Entry{
		{ID: "allow", Prefix: mustPrefix("10.0.0.0/8"), Action: ActionAllow},
		{ID: "block", Prefix: mustPrefix("10.1.2.3/32"), Action: ActionBlock},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Allow(netip.MustParseAddr("10.1.2.3")) {
		t.Error("allow should take precedence")
	}
	if set.Block(netip.MustParseAddr("10.1.2.3")) {
		t.Error("block should not report true when allow wins")
	}
}

func TestV4Mapped(t *testing.T) {
	set, _ := Build([]Entry{{ID: "b", Prefix: mustPrefix("1.2.3.0/24"), Action: ActionBlock}})
	a := netip.MustParseAddr("::ffff:1.2.3.4")
	if !set.Block(a) {
		t.Errorf("v4-mapped address should match v4 prefix")
	}
}
