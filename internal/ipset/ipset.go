// Package ipset provides a compact, allocation-free prefix lookup for IPv4 and
// IPv6 allow/block lists. Lookups walk a binary trie instead of looping over
// string prefixes.
package ipset

import (
	"fmt"
	"net/netip"
)

// Action is the effect of an IP rule.
type Action uint8

const (
	ActionBlock Action = iota
	ActionAllow
)

func (a Action) String() string {
	if a == ActionAllow {
		return "allow"
	}
	return "block"
}

// Entry is a single prefix rule.
type Entry struct {
	ID     string
	Prefix netip.Prefix
	Action Action
	Note   string
}

// Set is an immutable compiled IP rule set.
type Set struct {
	allow *trie
	block *trie
	size  int
}

// Build compiles entries into a Set. The most specific matching prefix is
// irrelevant: allow entries always take precedence over block entries, per
// the documented evaluation order (IP allow -> IP block -> WAF rules).
func Build(entries []Entry) (*Set, error) {
	s := &Set{allow: newTrie(), block: newTrie()}
	for _, e := range entries {
		p := e.Prefix
		if !p.IsValid() {
			return nil, fmt.Errorf("ip rule %s: invalid prefix", e.ID)
		}
		a := p.Addr()
		bits := p.Bits()
		if a.Is4In6() {
			a = a.Unmap()
			bits -= 96
		}
		p = netip.PrefixFrom(a, bits).Masked()
		switch e.Action {
		case ActionAllow:
			s.allow.insert(p)
		case ActionBlock:
			s.block.insert(p)
		default:
			return nil, fmt.Errorf("ip rule %s: unknown action", e.ID)
		}
		s.size++
	}
	return s, nil
}

// Size returns the number of compiled entries.
func (s *Set) Size() int { return s.size }

// ActionFor returns the effective action for addr, if any. Allow wins.
func (s *Set) ActionFor(addr netip.Addr) (Action, bool) {
	if !addr.IsValid() {
		return 0, false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		if s.allow.contains4(addr) {
			return ActionAllow, true
		}
		if s.block.contains4(addr) {
			return ActionBlock, true
		}
		return 0, false
	}
	if s.allow.contains16(addr) {
		return ActionAllow, true
	}
	if s.block.contains16(addr) {
		return ActionBlock, true
	}
	return 0, false
}

// Allow reports whether addr is explicitly allowed.
func (s *Set) Allow(addr netip.Addr) bool {
	a, ok := s.ActionFor(addr)
	return ok && a == ActionAllow
}

// Block reports whether addr is explicitly blocked.
func (s *Set) Block(addr netip.Addr) bool {
	a, ok := s.ActionFor(addr)
	return ok && a == ActionBlock
}

type trie struct {
	root *node
}

type node struct {
	child [2]*node
	match bool
}

func newTrie() *trie { return &trie{root: &node{}} }

func (t *trie) insert(p netip.Prefix) {
	a := p.Addr()
	bits := p.Bits()
	var raw []byte
	if a.Is4() {
		b := a.As4()
		raw = b[:]
	} else {
		b := a.As16()
		raw = b[:]
	}
	cur := t.root
	for i := 0; i < bits; i++ {
		bit := (raw[i>>3] >> (7 - uint(i&7))) & 1
		if cur.child[bit] == nil {
			cur.child[bit] = &node{}
		}
		cur = cur.child[bit]
	}
	cur.match = true
}

func (t *trie) contains4(a netip.Addr) bool {
	raw := a.As4()
	return t.contains(raw[:], 32)
}

func (t *trie) contains16(a netip.Addr) bool {
	raw := a.As16()
	return t.contains(raw[:], 128)
}

func (t *trie) contains(raw []byte, nbits int) bool {
	cur := t.root
	if cur.match {
		return true
	}
	for i := 0; i < nbits; i++ {
		bit := (raw[i>>3] >> (7 - uint(i&7))) & 1
		cur = cur.child[bit]
		if cur == nil {
			return false
		}
		if cur.match {
			return true
		}
	}
	return false
}
