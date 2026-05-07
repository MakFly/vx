package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

// SQLi detects SQL injection vulnerabilities via error-based and time-based techniques.
type SQLi struct{}

func (s *SQLi) Name() string        { return "sqli" }
func (s *SQLi) Description() string { return "SQL injection detection via error-based and time-based techniques" }

// sqlErrorPattern groups a compiled regex with its database engine name.
type sqlErrorPattern struct {
	engine  string
	pattern *regexp.Regexp
}

// sqlPayload is an injection string used for error-based detection.
type sqlPayload struct {
	name  string
	value string
}

var errorPayloads = []sqlPayload{
	{name: "single-quote", value: "'"},
	{name: "double-quote", value: `"`},
	{name: "OR tautology", value: "' OR '1'='1"},
	{name: "UNION SELECT", value: "1 UNION SELECT NULL--"},
	{name: "CONVERT version", value: "1' AND 1=CONVERT(int,@@version)--"},
}

var sqlErrorPatterns []sqlErrorPattern

func init() {
	// Pre-compile all SQL error detection regexes (case-insensitive).
	raw := []struct {
		engine  string
		pattern string
	}{
		// MySQL
		{"MySQL", `you have an error in your sql syntax`},
		{"MySQL", `mysql_fetch`},
		{"MySQL", `mysql_num_rows`},
		{"MySQL", `supplied argument is not a valid MySQL`},
		// PostgreSQL
		{"PostgreSQL", `pg_query`},
		{"PostgreSQL", `pg_exec`},
		{"PostgreSQL", `unterminated quoted string`},
		{"PostgreSQL", `syntax error at or near`},
		// MSSQL
		{"MSSQL", `unclosed quotation mark`},
		{"MSSQL", `microsoft ole db`},
		{"MSSQL", `sql server`},
		{"MSSQL", `incorrect syntax near`},
		// SQLite
		{"SQLite", `sqlite3_`},
		{"SQLite", `unrecognized token`},
		{"SQLite", `SQLITE_ERROR`},
		// Oracle
		{"Oracle", `ORA-\d{5}`},
		{"Oracle", `oracle error`},
		{"Oracle", `quoted string not properly terminated`},
		// Generic
		{"Generic", `SQL syntax`},
		{"Generic", `sql error`},
		{"Generic", `database error`},
		{"Generic", `query failed`},
	}
	for _, r := range raw {
		sqlErrorPatterns = append(sqlErrorPatterns, sqlErrorPattern{
			engine:  r.engine,
			pattern: regexp.MustCompile(`(?i)` + r.pattern),
		})
	}
}

// sqliEndpoint represents a URL + parameter to test.
type sqliEndpoint struct {
	url   string
	param string
	name  string
}

func (s *SQLi) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	base := strings.TrimRight(cfg.TargetURL, "/")

	var findings []engine.Finding

	// Phase 1: discover testable endpoints from the homepage.
	_, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	html := string(body)

	endpoints := s.discoverEndpoints(html, base)

	// Phase 2: error-based detection on every endpoint.
	seen := make(map[string]bool)
	var timeCandidates []sqliEndpoint

	for _, ep := range endpoints {
		epFindings, injectable := s.testErrorBased(client, ep, cfg)
		for _, f := range epFindings {
			key := f.Title + "|" + f.CWE
			if !seen[key] {
				seen[key] = true
				findings = append(findings, f)
			}
		}
		// Keep endpoints that returned SQL errors as candidates for time-based.
		if injectable {
			timeCandidates = append(timeCandidates, ep)
		}
	}

	// Phase 3: time-based detection on at most 2 endpoints.
	if len(timeCandidates) == 0 && len(endpoints) > 0 {
		// If no error-based hits, try time-based on first 2 regular endpoints.
		limit := 2
		if len(endpoints) < limit {
			limit = len(endpoints)
		}
		timeCandidates = endpoints[:limit]
	}
	if len(timeCandidates) > 2 {
		timeCandidates = timeCandidates[:2]
	}
	for _, ep := range timeCandidates {
		tbFindings := s.testTimeBased(client, ep, cfg)
		for _, f := range tbFindings {
			key := f.Title + "|" + f.CWE
			if !seen[key] {
				seen[key] = true
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

// discoverEndpoints finds search forms, common search paths, and common ID params.
func (s *SQLi) discoverEndpoints(html string, base string) []sqliEndpoint {
	var endpoints []sqliEndpoint
	seen := make(map[string]bool)

	addUnique := func(ep sqliEndpoint) {
		key := ep.url + "|" + ep.param
		if !seen[key] {
			seen[key] = true
			endpoints = append(endpoints, ep)
		}
	}

	// Parse <form> elements for text inputs.
	formBlockRe := regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']*)["'][^>]*>(.*?)</form>`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']*)["']`)
	typeRe := regexp.MustCompile(`(?i)type=["'](hidden|submit|checkbox|radio|file|image)["']`)

	formBlocks := formBlockRe.FindAllStringSubmatch(html, 10)
	for _, fb := range formBlocks {
		action := fb[1]
		if action == "" || action == "#" {
			continue
		}
		if !strings.HasPrefix(action, "http") {
			action = base + "/" + strings.TrimLeft(action, "/")
		}
		formHTML := fb[2]
		inputs := inputRe.FindAllStringSubmatch(formHTML, -1)
		for _, input := range inputs {
			paramName := input[1]
			if paramName == "" || typeRe.MatchString(input[0]) {
				continue
			}
			addUnique(sqliEndpoint{url: action, param: paramName, name: "form-" + paramName})
		}
	}

	// Common search URL patterns.
	commonSearch := []sqliEndpoint{
		{url: base + "/recherche", param: "search_query", name: "search (PrestaShop)"},
		{url: base + "/search", param: "q", name: "search-q"},
		{url: base + "/search", param: "s", name: "search-s"},
	}
	for _, ep := range commonSearch {
		addUnique(ep)
	}

	// Common ID/numeric parameter endpoints.
	commonID := []sqliEndpoint{
		{url: base + "/", param: "id", name: "param-id"},
		{url: base + "/", param: "page", name: "param-page"},
		{url: base + "/", param: "cat", name: "param-cat"},
	}
	for _, ep := range commonID {
		addUnique(ep)
	}

	return endpoints
}

// testErrorBased injects payloads and looks for SQL error patterns in the response.
// Returns findings and whether at least one injection triggered a SQL error.
func (s *SQLi) testErrorBased(client *http.Client, ep sqliEndpoint, cfg *engine.Config) ([]engine.Finding, bool) {
	var findings []engine.Finding
	injectable := false

	// Get baseline response to check for SPA catch-all and pre-existing errors.
	baselineURL := fmt.Sprintf("%s?%s=test123", ep.url, ep.param)
	_, baselineBody, err := doGet(client, baselineURL, cfg.UserAgent)
	if err != nil {
		return findings, false
	}
	baselineHTML := string(baselineBody)

	// Skip SPA catch-all pages.
	if IsSPACatchAll(baselineHTML) {
		return findings, false
	}

	// Collect any SQL error patterns already present in the baseline.
	baselineErrors := make(map[string]bool)
	for _, ep := range sqlErrorPatterns {
		if ep.pattern.MatchString(baselineHTML) {
			baselineErrors[ep.engine+":"+ep.pattern.String()] = true
		}
	}

	for _, payload := range errorPayloads {
		encoded := url.QueryEscape(payload.value)
		testURL := fmt.Sprintf("%s?%s=%s", ep.url, ep.param, encoded)

		_, respBody, err := doGet(client, testURL, cfg.UserAgent)
		if err != nil {
			continue
		}
		respHTML := string(respBody)

		if IsSPACatchAll(respHTML) {
			continue
		}

		for _, errPat := range sqlErrorPatterns {
			if !errPat.pattern.MatchString(respHTML) {
				continue
			}

			patKey := errPat.engine + ":" + errPat.pattern.String()

			// If this error was already in the baseline, it's a pre-existing leak, not injection.
			if baselineErrors[patKey] {
				continue
			}

			match := errPat.pattern.FindString(respHTML)

			injectable = true
			findings = append(findings, engine.Finding{
				Module:   s.Name(),
				Severity: engine.SevCritical,
				Title:    fmt.Sprintf("SQL injection (error-based) via %s on %s=%s", payload.name, ep.name, ep.param),
				Description: fmt.Sprintf(
					"Injecting %q into parameter %s at %s triggers a %s error message, "+
						"indicating the input reaches a SQL query without proper sanitization.",
					payload.value, ep.param, ep.url, errPat.engine,
				),
				Evidence:    fmt.Sprintf("Payload: %s | DB engine: %s | Error: %s", payload.value, errPat.engine, truncate(match, 120)),
				CWE:         "CWE-89",
				Remediation: "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings.",
				CVSS:        9.8,
			})

			// One finding per payload is enough — don't duplicate for multiple matching patterns.
			break
		}
	}

	// Also report if the baseline itself leaks SQL error messages (information disclosure).
	if len(baselineErrors) > 0 && !injectable {
		var engines []string
		seenEngines := make(map[string]bool)
		for _, ep := range sqlErrorPatterns {
			if ep.pattern.MatchString(baselineHTML) && !seenEngines[ep.engine] {
				seenEngines[ep.engine] = true
				engines = append(engines, ep.engine)
			}
		}
		findings = append(findings, engine.Finding{
			Module:      s.Name(),
			Severity:    engine.SevMedium,
			Title:       fmt.Sprintf("SQL error message exposed at %s", ep.name),
			Description: fmt.Sprintf("The endpoint %s exposes database error messages (%s) even with benign input. This leaks internal implementation details.", ep.url, strings.Join(engines, ", ")),
			Evidence:    fmt.Sprintf("DB engine(s): %s", strings.Join(engines, ", ")),
			CWE:         "CWE-209",
			Remediation: "Suppress detailed database errors in production. Use generic error pages and log details server-side only.",
			CVSS:        5.3,
		})
	}

	return findings, injectable
}

// testTimeBased uses delay-based payloads to detect blind SQL injection.
func (s *SQLi) testTimeBased(client *http.Client, ep sqliEndpoint, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Measure baseline response time.
	baselineURL := fmt.Sprintf("%s?%s=test123", ep.url, ep.param)
	baseStart := time.Now()
	_, _, err := doGet(client, baselineURL, cfg.UserAgent)
	if err != nil {
		return findings
	}
	baselineDuration := time.Since(baseStart)

	// Only proceed if baseline is fast enough (< 1s).
	if baselineDuration > 1*time.Second {
		return findings
	}

	timePayloads := []struct {
		name    string
		value   string
		dbHint  string
		delay   time.Duration
	}{
		{name: "SLEEP (MySQL)", value: "' OR SLEEP(3)--", dbHint: "MySQL", delay: 3 * time.Second},
		{name: "WAITFOR (MSSQL)", value: "'; WAITFOR DELAY '0:0:3'--", dbHint: "MSSQL", delay: 3 * time.Second},
	}

	for _, payload := range timePayloads {
		encoded := url.QueryEscape(payload.value)
		testURL := fmt.Sprintf("%s?%s=%s", ep.url, ep.param, encoded)

		start := time.Now()
		_, respBody, err := doGet(client, testURL, cfg.UserAgent)
		if err != nil {
			continue
		}
		elapsed := time.Since(start)

		if IsSPACatchAll(string(respBody)) {
			continue
		}

		// If the response took significantly longer than baseline and exceeds the delay threshold,
		// it's a candidate for blind SQLi.
		if elapsed >= payload.delay && elapsed > baselineDuration+2*time.Second {
			findings = append(findings, engine.Finding{
				Module:   s.Name(),
				Severity: engine.SevHigh,
				Title:    fmt.Sprintf("Possible blind SQL injection (time-based) via %s on %s=%s", payload.name, ep.name, ep.param),
				Description: fmt.Sprintf(
					"Injecting a %s delay payload into parameter %s at %s caused the response "+
						"time to increase from %s to %s, suggesting the SQL statement executed the delay.",
					payload.dbHint, ep.param, ep.url,
					baselineDuration.Round(time.Millisecond), elapsed.Round(time.Millisecond),
				),
				Evidence:    fmt.Sprintf("Payload: %s | Baseline: %s | Injected: %s", payload.value, baselineDuration.Round(time.Millisecond), elapsed.Round(time.Millisecond)),
				CWE:         "CWE-89",
				Remediation: "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings.",
				CVSS:        8.0,
			})
		}
	}

	return findings
}
