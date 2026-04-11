package modules

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

type Login struct{}

func (l *Login) Name() string        { return "login" }
func (l *Login) Description() string { return "Login form security audit" }

// Common paths where login forms are typically found
var loginPaths = []string{
	"/login", "/signin", "/sign-in", "/auth/login", "/user/login",
	"/admin/login", "/admin", "/account/login", "/connexion",
	"/wp-login.php", "/wp-admin",
}

func (l *Login) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	var findings []engine.Finding

	// Discover login form
	formURL, formHTML, err := l.findLoginForm(client, cfg)
	if err != nil || formURL == "" {
		return findings, nil // No login form found — nothing to audit
	}

	// Check HTTPS
	if !strings.HasPrefix(formURL, "https://") {
		findings = append(findings, engine.Finding{
			Module:      l.Name(),
			Severity:    engine.SevCritical,
			Title:       "Login form served over HTTP",
			Description: "Credentials are transmitted in plaintext — trivially interceptable",
			Evidence:    fmt.Sprintf("Login form at: %s", formURL),
			CWE:         "CWE-319",
			CVSS:        9.1,
			Remediation: "Serve the login form exclusively over HTTPS and redirect HTTP to HTTPS",
		})
	}

	// Analyze the form
	findings = append(findings, l.analyzeForm(formHTML, formURL)...)

	// Test rate limiting
	findings = append(findings, l.testRateLimiting(client, cfg, formURL)...)

	return findings, nil
}

func (l *Login) findLoginForm(client *http.Client, cfg *engine.Config) (string, string, error) {
	// First try the target URL itself
	resp, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err == nil && resp.StatusCode == 200 {
		html := string(body)
		if hasPasswordField(html) {
			return cfg.TargetURL, html, nil
		}
	}

	// Probe common login paths
	for _, path := range loginPaths {
		url := strings.TrimRight(cfg.TargetURL, "/") + path
		resp, body, err := doGet(client, url, cfg.UserAgent)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		html := string(body)
		if hasPasswordField(html) {
			return url, html, nil
		}
	}

	return "", "", nil
}

var passwordFieldRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']password["'][^>]*>`)
var formMethodRe = regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']([^"']*)["'][^>]*>`)
var csrfTokenRe = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["'](_?csrf[_-]?token|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken|_csrf)["'][^>]*>`)
var autocompleteOffRe = regexp.MustCompile(`(?i)autocomplete\s*=\s*["'](off|new-password|current-password)["']`)

func hasPasswordField(html string) bool {
	return passwordFieldRe.MatchString(html)
}

func (l *Login) analyzeForm(html, formURL string) []engine.Finding {
	var findings []engine.Finding

	// Find the form containing the password field
	// Extract method
	methods := formMethodRe.FindAllStringSubmatch(html, -1)
	hasGetMethod := false
	for _, m := range methods {
		if len(m) > 1 && strings.EqualFold(m[1], "GET") {
			hasGetMethod = true
		}
	}

	if hasGetMethod {
		findings = append(findings, engine.Finding{
			Module:      l.Name(),
			Severity:    engine.SevHigh,
			Title:       "Login form uses GET method",
			Description: "Credentials are sent as URL parameters and will appear in browser history, server logs, and referrer headers",
			Evidence:    fmt.Sprintf("Form method=GET at %s", formURL),
			CWE:         "CWE-598",
			CVSS:        7.5,
			Remediation: "Change the form method to POST",
		})
	}

	// Check CSRF token
	if !csrfTokenRe.MatchString(html) {
		// Also check for meta tag CSRF tokens
		metaCsrf := regexp.MustCompile(`(?i)<meta[^>]*name\s*=\s*["']csrf[^"']*["'][^>]*>`)
		if !metaCsrf.MatchString(html) {
			findings = append(findings, engine.Finding{
				Module:      l.Name(),
				Severity:    engine.SevMedium,
				Title:       "No CSRF token detected in login form",
				Description: "Login form does not appear to include a CSRF token, which may allow login CSRF attacks",
				Evidence:    fmt.Sprintf("No CSRF hidden input found at %s", formURL),
				CWE:         "CWE-352",
				CVSS:        5.4,
				Remediation: "Add a CSRF token to the login form (e.g. hidden input with a server-generated token)",
			})
		}
	}

	// Check autocomplete on password field
	passwordFields := passwordFieldRe.FindAllString(html, -1)
	for _, field := range passwordFields {
		if !autocompleteOffRe.MatchString(field) {
			// Only flag if autocomplete is explicitly not handled
			// Modern browsers ignore autocomplete=off for passwords anyway, so this is low severity
			findings = append(findings, engine.Finding{
				Module:      l.Name(),
				Severity:    engine.SevLow,
				Title:       "Password field allows autocomplete",
				Description: "The password input does not disable autocomplete. Stored credentials could be accessed if the device is compromised.",
				Evidence:    truncate(field, 120),
				CWE:         "CWE-522",
				Remediation: "Add autocomplete=\"current-password\" or autocomplete=\"off\" to the password field",
			})
			break // Only report once
		}
	}

	return findings
}

func (l *Login) testRateLimiting(client *http.Client, cfg *engine.Config, formURL string) []engine.Finding {
	var findings []engine.Finding

	// Send 5 rapid requests to the login page and check for rate limiting
	got429 := false
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest("POST", formURL, strings.NewReader("username=test@nonexistent.invalid&password=wrongpassword123"))
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 429 {
			got429 = true
			break
		}

		// Small delay to avoid being too aggressive
		time.Sleep(100 * time.Millisecond)
	}

	if !got429 {
		findings = append(findings, engine.Finding{
			Module:      l.Name(),
			Severity:    engine.SevMedium,
			Title:       "No rate limiting detected on login",
			Description: "5 rapid login attempts did not trigger a 429 response. The login form may be vulnerable to brute-force attacks.",
			Evidence:    fmt.Sprintf("5 POST requests to %s — no 429 response received", formURL),
			CWE:         "CWE-307",
			CVSS:        5.3,
			Remediation: "Implement rate limiting on the login endpoint (e.g. max 5 attempts per minute per IP)",
		})
	}

	return findings
}
