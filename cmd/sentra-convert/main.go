// Command sentra-convert converts rules from other WAF formats into a Sentra
// rule database.
//
// The first supported source is the caddy-waf rule format used historically on
// txsp/txsp2/gate: a JSON array of rules with {id, phase, pattern, targets,
// severity, action, score, priority, description}. IP allow/block lists are
// plain text files with one address or CIDR per line.
//
// It writes a Sentra SQLite database (the format the Caddy module consumes) and
// can also print the converted rules as Sentra JSON for review.
//
// Example:
//
//	sentra-convert \
//	  -db sentra.db \
//	  -rule rules.json -rule legacy-rules.json \
//	  -ip-block ip_blacklist.txt -ip-allow ip_whitelist.txt
package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Xwudao/sentra/internal/defaults"
	"github.com/Xwudao/sentra/internal/rule"
	"github.com/Xwudao/sentra/internal/storage"
)

// caddyWAFRule mirrors the JSON schema of github.com/fabriziosalmi/caddy-waf.
type caddyWAFRule struct {
	ID          string   `json:"id"`
	Phase       int      `json:"phase"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Severity    string   `json:"severity"`
	Action      string   `json:"action"`
	Score       int      `json:"score"`
	Priority    int      `json:"priority"`
	Description string   `json:"description"`
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sentra-convert:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		ruleFiles  stringList
		dbPath     = flag.String("db", "", "output Sentra SQLite database (omit with -print-json)")
		ipBlock    = flag.String("ip-block", "", "plain-text IP/CIDR block list")
		ipAllow    = flag.String("ip-allow", "", "plain-text IP/CIDR allow list")
		transforms = flag.String("transforms", "url_decode,remove_nulls", "transforms applied to every converted rule")
		idPrefix   = flag.String("id-prefix", "fw-", "prefix added to converted rule IDs")
		noDefaults = flag.Bool("no-defaults", false, "do not seed Sentra's built-in ruleset")
		printJSON  = flag.Bool("print-json", false, "print converted rules as Sentra JSON and exit")
	)
	flag.Var(&ruleFiles, "rule", "caddy-waf rules.json to convert (repeatable)")
	flag.Parse()

	if len(ruleFiles) == 0 && *ipBlock == "" && *ipAllow == "" {
		return fmt.Errorf("nothing to convert: provide -rule and/or -ip-block/-ip-allow")
	}
	if !*printJSON && *dbPath == "" {
		return fmt.Errorf("-db is required unless -print-json is set")
	}

	xf := splitTransforms(*transforms)

	rules, err := loadAndConvert(ruleFiles, *idPrefix, xf)
	if err != nil {
		return err
	}

	blocks, err := readIPList(*ipBlock)
	if err != nil {
		return err
	}
	allows, err := readIPList(*ipAllow)
	if err != nil {
		return err
	}

	// Fail before touching any database if the converted ruleset cannot compile
	// against the built-in rules Sentra would seed.
	preview := rules
	if !*noDefaults {
		preview = append(append([]rule.Rule{}, defaults.Rules()...), rules...)
	}
	if _, err := rule.Compile(preview, 0); err != nil {
		return fmt.Errorf("converted rules failed to compile: %w", err)
	}

	if *printJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rules)
	}

	ctx := context.Background()
	store, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if !*noDefaults {
		if err := defaults.Seed(ctx, store); err != nil {
			return fmt.Errorf("seed defaults: %w", err)
		}
	}

	for _, r := range rules {
		if err := store.UpsertRule(ctx, r, false); err != nil {
			return fmt.Errorf("upsert rule %s: %w", r.ID, err)
		}
	}

	nBlock, err := importIPRules(ctx, store, blocks, "block")
	if err != nil {
		return err
	}
	nAllow, err := importIPRules(ctx, store, allows, "allow")
	if err != nil {
		return err
	}

	// Collapse the WAL back into the main file so the database can be copied
	// as a single artifact.
	if _, err := store.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}

	seeded := 0
	if !*noDefaults {
		seeded = len(defaults.Rules())
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d built-in + %d converted rules, %d block / %d allow IP entries\n",
		*dbPath, seeded, len(rules), nBlock, nAllow)
	return nil
}

func splitTransforms(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadAndConvert(files []string, prefix string, transforms []string) ([]rule.Rule, error) {
	var out []rule.Rule
	seen := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var src []caddyWAFRule
		if err := json.Unmarshal(raw, &src); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		for _, r := range src {
			conv, err := convert(r, prefix, transforms, f)
			if err != nil {
				return nil, err
			}
			if seen[conv.ID] {
				return nil, fmt.Errorf("duplicate converted rule id %q", conv.ID)
			}
			seen[conv.ID] = true
			if err := rule.Validate(&conv); err != nil {
				return nil, fmt.Errorf("rule %s: %w", conv.ID, err)
			}
			out = append(out, conv)
		}
	}
	return out, nil
}

func convert(r caddyWAFRule, prefix string, transforms []string, source string) (rule.Rule, error) {
	if r.ID == "" {
		return rule.Rule{}, fmt.Errorf("rule without id in %s", source)
	}
	// caddy-waf phases follow the ModSecurity convention: 1 = request
	// headers, 2 = request body. Both are request-side and map onto Sentra's
	// single request phase. 3/4 (response) are unsupported.
	if r.Phase > 2 {
		return rule.Rule{}, fmt.Errorf("rule %s: unsupported response phase %d", r.ID, r.Phase)
	}
	targets := make([]string, 0, len(r.Targets))
	for _, t := range r.Targets {
		mapped, err := mapTarget(t)
		if err != nil {
			return rule.Rule{}, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		targets = append(targets, mapped)
	}
	if len(targets) == 0 {
		return rule.Rule{}, fmt.Errorf("rule %s: no targets", r.ID)
	}

	action := rule.Action(strings.ToLower(r.Action))
	if action == "" {
		action = rule.ActionBlock
	}
	severity := rule.Severity(strings.ToLower(r.Severity))
	if severity == "" {
		severity = rule.SeverityMedium
	}

	id := prefix + sanitizeID(r.ID)
	out := rule.Rule{
		ID:          id,
		Name:        humanize(r.ID),
		Enabled:     true,
		Phase:       rule.PhaseRequest,
		Targets:     targets,
		Operator:    rule.OpRegex,
		Value:       r.Pattern,
		Transforms:  append([]string(nil), transforms...),
		Action:      action,
		Score:       r.Score,
		Severity:    severity,
		Priority:    r.Priority,
		Tags:        []string{"converted", "caddy-waf"},
		Description: strings.TrimSpace(r.Description),
	}
	out.Normalize()
	return out, nil
}

// mapTarget translates a caddy-waf target into a Sentra target.
func mapTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	upper := strings.ToUpper(t)
	if rest, ok := strings.CutPrefix(upper, "HEADERS:"); ok {
		return "header:" + strings.ToLower(strings.TrimSpace(rest)), nil
	}
	switch upper {
	case "ARGS", "ARGS_GET", "QUERY", "QUERYSTRING":
		return "query", nil
	case "ARGS_POST", "POST", "BODY", "REQUEST_BODY":
		return "body", nil
	case "URI", "URL", "REQUEST_URI":
		return "uri", nil
	case "PATH":
		return "path", nil
	case "HEADERS", "HEADER":
		return "header", nil
	case "COOKIES", "COOKIE":
		return "cookie", nil
	case "METHOD":
		return "method", nil
	case "HOST":
		return "host", nil
	default:
		return "", fmt.Errorf("unsupported target %q", t)
	}
}

func sanitizeID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	var b strings.Builder
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func humanize(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// readIPList parses a plain-text list; blank lines and # comments are ignored.
// Invalid entries are reported so a broken list does not silently shrink.
func readIPList(path string) ([]netip.Prefix, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, aerr := netip.ParseAddr(line)
			if aerr != nil {
				return nil, fmt.Errorf("%s:%d: invalid IP/CIDR %q", path, i+1, line)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		if seen[p.String()] {
			continue
		}
		seen[p.String()] = true
		out = append(out, p)
	}
	return out, nil
}

func importIPRules(ctx context.Context, store storage.Store, prefixes []netip.Prefix, action string) (int, error) {
	for _, p := range prefixes {
		id := ipRuleID(action, p.String())
		if err := store.UpsertIPRule(ctx, storage.IPRule{
			ID:     id,
			CIDR:   p.String(),
			Action: action,
			Note:   "imported from caddy-waf list",
		}); err != nil {
			return 0, err
		}
	}
	return len(prefixes), nil
}

func ipRuleID(action, cidr string) string {
	sum := sha1.Sum([]byte(action + "|" + cidr))
	return action + "-" + hex.EncodeToString(sum[:8])
}
