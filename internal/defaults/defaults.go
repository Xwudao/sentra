// Package defaults contains Sentra's built-in, conservative ruleset. The
// rules intentionally favour low false-positive rates over exhaustive
// coverage; they do not claim OWASP CRS compatibility.
package defaults

import (
	"context"

	"github.com/Xwudao/sentra/internal/rule"
	"github.com/Xwudao/sentra/internal/storage"
)

// seedKey records that defaults have been installed so that deleting every
// rule does not silently re-add them on the next restart.
const seedKey = "defaults_seeded"

// Rules returns the built-in ruleset.
func Rules() []rule.Rule {
	return []rule.Rule{
		{
			ID: "sqli-union-select", Name: "SQL injection: UNION SELECT", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body", "cookie", "header:user-agent"},
			Operator: rule.OpRegex, Value: `(?i)\bunion\b[\s/*!]+select\b`,
			Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 100,
			Tags: []string{"sqli"}, Description: "Detects UNION SELECT injection attempts.",
		},
		{
			ID: "sqli-boolean", Name: "SQL injection: boolean tautology", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body"},
			Operator: rule.OpRegex, Value: `(?i)(?:\bor\b|\band\b)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?`,
			Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace", "lowercase"},
			Action:     rule.ActionLog, Score: 5, Severity: rule.SeverityMedium, Priority: 80,
			Tags: []string{"sqli"}, Description: "Detects boolean tautology patterns; anomaly scores only.",
		},
		{
			ID: "sqli-time-based", Name: "SQL injection: time based", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body"},
			Operator: rule.OpRegex, Value: `(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`,
			Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 100,
			Tags: []string{"sqli"}, Description: "Detects time-based SQL injection functions.",
		},
		{
			ID: "xss-script-tag", Name: "XSS: script tag", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body", "header:referer"},
			Operator: rule.OpRegex, Value: `(?i)<\s*script`,
			Transforms: []string{"url_decode", "html_decode", "remove_nulls", "lowercase"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 100,
			Tags: []string{"xss"}, Description: "Detects script tags in request data.",
		},
		{
			ID: "xss-event-handler", Name: "XSS: event handler attribute", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body"},
			Operator: rule.OpRegex, Value: `(?i)<[^>]{0,200}\bon(?:error|load|click|mouseover|focus|submit)\s*=`,
			Transforms: []string{"url_decode", "html_decode", "remove_nulls", "lowercase"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 90,
			Tags: []string{"xss"}, Description: "Detects inline event handler injection.",
		},
		{
			ID: "xss-javascript-uri", Name: "XSS: javascript URI", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body"},
			Operator: rule.OpContains, Value: "javascript:",
			Transforms: []string{"url_decode", "html_decode", "remove_nulls", "lowercase"},
			Action:     rule.ActionLog, Score: 5, Severity: rule.SeverityMedium, Priority: 60,
			Tags: []string{"xss"}, Description: "Detects javascript: URIs (logged, anomaly scored).",
		},
		{
			ID: "path-traversal", Name: "Path traversal", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"path", "uri", "query"},
			Operator: rule.OpRegex, Value: `(?:\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)`,
			Transforms: []string{"url_decode", "remove_nulls"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 100,
			Tags: []string{"lfi", "traversal"}, Description: "Detects directory traversal sequences.",
		},
		{
			ID: "cmd-injection", Name: "Command injection", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body", "header:user-agent"},
			Operator: rule.OpRegex, Value: `(?i)(?:;|\||&&|\|\|)\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|nc|netcat|python|perl|php)\b`,
			Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 95,
			Tags: []string{"rce"}, Description: "Detects common shell command chaining.",
		},
		{
			ID: "log4shell-jndi", Name: "Log4Shell JNDI lookup", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"query", "body", "header", "cookie"},
			Operator: rule.OpRegex, Value: `(?i)\$\{jndi:(?:ldap|ldaps|rmi|dns|http|iiop)://`,
			Transforms: []string{"url_decode", "remove_nulls", "lowercase"},
			Action:     rule.ActionBlock, Score: 15, Severity: rule.SeverityCritical, Priority: 120,
			Tags: []string{"rce", "log4shell"}, Description: "Detects Log4Shell JNDI payloads.",
		},
		{
			ID: "scanner-user-agent", Name: "Known scanner user agent", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"header:user-agent"},
			Operator: rule.OpKeywordSet, Values: []string{
				"sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus",
				"nuclei", "wpscan", "dirbuster", "gobuster", "zgrab", "jaeles",
			},
			Transforms: []string{"lowercase"},
			Action:     rule.ActionBlock, Score: 5, Severity: rule.SeverityMedium, Priority: 70,
			Tags: []string{"scanner"}, Description: "Blocks well-known vulnerability scanners by user agent.",
		},
		{
			ID: "sensitive-files", Name: "Sensitive file access", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"path"},
			Operator: rule.OpRegex, Value: `(?i)(?:/\.git/|/\.svn/|/\.env(?:\.|$)|/\.aws/|/id_rsa|/\.ssh/|wp-config\.php|/\.htaccess|/web\.config)`,
			Transforms: []string{"url_decode", "lowercase"},
			Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh, Priority: 90,
			Tags: []string{"recon"}, Description: "Blocks access to common sensitive files.",
		},
		{
			ID: "common-probes", Name: "Common exploit probe paths", Enabled: true,
			Phase: rule.PhaseRequest, Targets: []string{"path"},
			Operator: rule.OpRegex, Value: `(?i)/(?:phpmyadmin|phpunit|vendor/phpunit|actuator/env|jmx-console|solr/admin|console/login|\.\.;/)`,
			Transforms: []string{"url_decode", "lowercase"},
			Action:     rule.ActionLog, Score: 5, Severity: rule.SeverityMedium, Priority: 50,
			Tags: []string{"recon"}, Description: "Logs requests for common management/exploit endpoints.",
		},
	}
}

// Seed installs the default rules the first time the database is used.
func Seed(ctx context.Context, store storage.Store) error {
	if _, err := store.GetSetting(ctx, seedKey); err == nil {
		return nil
	}
	existing, err := store.ListRules(ctx)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		for _, r := range Rules() {
			if err := store.UpsertRule(ctx, r, true); err != nil {
				return err
			}
		}
	}
	return store.SetSetting(ctx, seedKey, []byte(`true`))
}
