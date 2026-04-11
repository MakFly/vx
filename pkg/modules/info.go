package modules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type InfoDisclosure struct{}

func (i *InfoDisclosure) Name() string        { return "info" }
func (i *InfoDisclosure) Description() string { return "Information disclosure in HTML, JS, and comments" }

func (i *InfoDisclosure) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	_, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	html := string(body)

	var findings []engine.Finding

	findings = append(findings, i.checkTokens(html)...)
	findings = append(findings, i.checkSecrets(html)...)
	findings = append(findings, i.checkDebugInfo(html)...)
	findings = append(findings, i.checkComments(html)...)
	findings = append(findings, i.checkEmails(html)...)

	return findings, nil
}

func (i *InfoDisclosure) checkTokens(html string) []engine.Finding {
	var findings []engine.Finding

	// Static CSRF tokens exposed
	tokenPatterns := []struct {
		pattern *regexp.Regexp
		name    string
		desc    string
	}{
		{
			pattern: regexp.MustCompile(`"static_token"\s*:\s*"([a-f0-9]{32})"`),
			name:    "Static CSRF token exposed in JavaScript",
			desc:    "A static CSRF token is embedded in the page source. If this token doesn't rotate per-session, CSRF protection is weakened.",
		},
		{
			pattern: regexp.MustCompile(`"token"\s*:\s*"([a-f0-9]{32})"`),
			name:    "Session token exposed in JavaScript",
			desc:    "A session token is embedded in the page JavaScript object",
		},
	}

	for _, tp := range tokenPatterns {
		matches := tp.pattern.FindStringSubmatch(html)
		if len(matches) > 1 {
			findings = append(findings, engine.Finding{
				Module:      i.Name(),
				Severity:    engine.SevMedium,
				Title:       tp.name,
				Description: tp.desc,
				Evidence:    fmt.Sprintf("Token: %s...%s", matches[1][:8], matches[1][24:]),
				CWE:         "CWE-352",
			})
		}
	}

	return findings
}

func (i *InfoDisclosure) checkSecrets(html string) []engine.Finding {
	var findings []engine.Finding

	secretPatterns := []struct {
		pattern  *regexp.Regexp
		name     string
		severity engine.Severity
	}{
		{regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{10,})["']`), "API key exposed", engine.SevHigh},
		{regexp.MustCompile(`(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["']([^"']{10,})["']`), "Secret key exposed", engine.SevCritical},
		{regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']`), "Password in source", engine.SevCritical},
		{regexp.MustCompile(`(?i)(?:aws[_-]?access|AKIA)[A-Z0-9]{12,}`), "AWS access key", engine.SevCritical},
		{regexp.MustCompile(`(?i)sk_live_[a-zA-Z0-9]{20,}`), "Stripe live secret key", engine.SevCritical},
		{regexp.MustCompile(`(?i)pk_live_[a-zA-Z0-9]{20,}`), "Stripe live public key", engine.SevLow},
		{regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`), "GitHub personal access token", engine.SevCritical},
		{regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb)://[^\s<"']+`), "Database connection string", engine.SevCritical},
		{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`), "Bearer token", engine.SevHigh},
	}

	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllString(html, 3)
		for _, match := range matches {
			findings = append(findings, engine.Finding{
				Module:      i.Name(),
				Severity:    sp.severity,
				Title:       sp.name,
				Description: "Potential secret or credential found in page source",
				Evidence:    truncate(match, 60),
				CWE:         "CWE-798",
				Remediation: "Remove secrets from client-side code. Use server-side environment variables.",
			})
		}
	}

	// Tracking IDs (info level — not secrets but useful intel)
	trackingPatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`UA-\d{4,}-\d+`), "Google Analytics UA ID"},
		{regexp.MustCompile(`G-[A-Z0-9]{8,}`), "Google Analytics GA4 ID"},
		{regexp.MustCompile(`GTM-[A-Z0-9]{6,}`), "Google Tag Manager ID"},
		{regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,})['"]`), "Facebook Pixel ID"},
	}

	var trackingIDs []string
	for _, tp := range trackingPatterns {
		matches := tp.pattern.FindAllString(html, 5)
		for _, match := range matches {
			trackingIDs = append(trackingIDs, fmt.Sprintf("%s: %s", tp.name, match))
		}
	}

	if len(trackingIDs) > 0 {
		findings = append(findings, engine.Finding{
			Module:      i.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("%d tracking identifiers found", len(trackingIDs)),
			Description: "Tracking/analytics IDs visible in source (normal but useful for reconnaissance)",
			Evidence:    strings.Join(trackingIDs, " | "),
		})
	}

	return findings
}

func (i *InfoDisclosure) checkDebugInfo(html string) []engine.Finding {
	var findings []engine.Finding

	debugPatterns := []struct {
		pattern *regexp.Regexp
		name    string
		sev     engine.Severity
	}{
		{regexp.MustCompile(`(?i)"debug"\s*:\s*true`), "Debug mode enabled in JavaScript config", engine.SevHigh},
		{regexp.MustCompile(`(?i)(?:stack ?trace|at \w+\.\w+ \()`), "Stack trace in response", engine.SevHigh},
		{regexp.MustCompile(`(?i)/home/\w+/|/var/www/|C:\\\\(?:Users|inetpub)`), "Server file path disclosed", engine.SevMedium},
		{regexp.MustCompile(`(?i)(?:mysql|pgsql|sqlite)_(?:query|connect|error)`), "Database function reference", engine.SevMedium},
		{regexp.MustCompile(`(?i)phpinfo\(\)`), "phpinfo() call in source", engine.SevHigh},
	}

	for _, dp := range debugPatterns {
		matches := dp.pattern.FindAllString(html, 2)
		if len(matches) > 0 {
			// Skip false positive for "debug": false
			if dp.name == "Debug mode enabled in JavaScript config" {
				if regexp.MustCompile(`(?i)"debug"\s*:\s*false`).MatchString(html) {
					findings = append(findings, engine.Finding{
						Module:      i.Name(),
						Severity:    engine.SevInfo,
						Title:       "Debug mode explicitly disabled",
						Description: "debug: false found in JavaScript configuration (good)",
					})
					continue
				}
			}
			findings = append(findings, engine.Finding{
				Module:      i.Name(),
				Severity:    dp.sev,
				Title:       dp.name,
				Evidence:    truncate(matches[0], 80),
				CWE:         "CWE-200",
				Remediation: "Remove debug information from production output",
			})
		}
	}

	return findings
}

func (i *InfoDisclosure) checkComments(html string) []engine.Finding {
	var findings []engine.Finding

	commentRe := regexp.MustCompile(`<!--(.*?)-->`)
	comments := commentRe.FindAllStringSubmatch(html, -1)

	sensitiveCommentPatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)todo|fixme|hack|bug|xxx`), "TODO/FIXME comment"},
		{regexp.MustCompile(`(?i)password|secret|key|token|credential`), "Sensitive keyword in comment"},
		{regexp.MustCompile(`(?i)version\s*[:=]\s*[\d.]+`), "Version info in comment"},
		{regexp.MustCompile(`(?i)(?:remove|delete|temporary|temp)\s+(?:this|before|in\s+prod)`), "Temporary code marker"},
	}

	for _, comment := range comments {
		if len(comment) < 2 {
			continue
		}
		content := comment[1]
		if len(strings.TrimSpace(content)) < 5 {
			continue
		}

		for _, sp := range sensitiveCommentPatterns {
			if sp.pattern.MatchString(content) {
				findings = append(findings, engine.Finding{
					Module:      i.Name(),
					Severity:    engine.SevLow,
					Title:       fmt.Sprintf("HTML comment: %s", sp.name),
					Description: "Sensitive information found in HTML comment",
					Evidence:    truncate(strings.TrimSpace(content), 100),
					CWE:         "CWE-615",
					Remediation: "Remove sensitive HTML comments in production",
				})
				break
			}
		}
	}

	return findings
}

func (i *InfoDisclosure) checkEmails(html string) []engine.Finding {
	var findings []engine.Finding

	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	emails := emailRe.FindAllString(html, 20)

	// Filter out obviously generic ones
	var realEmails []string
	seen := make(map[string]bool)
	for _, email := range emails {
		lower := strings.ToLower(email)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		// Skip common false positives
		if strings.HasSuffix(lower, "@example.com") || strings.HasSuffix(lower, "@sentry.io") ||
			strings.Contains(lower, "schema.org") || strings.Contains(lower, "w3.org") {
			continue
		}
		realEmails = append(realEmails, email)
	}

	if len(realEmails) > 0 {
		findings = append(findings, engine.Finding{
			Module:      i.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("%d email addresses found in source", len(realEmails)),
			Description: "Email addresses visible in page source (potential phishing/spam targets)",
			Evidence:    strings.Join(realEmails, ", "),
		})
	}

	return findings
}
