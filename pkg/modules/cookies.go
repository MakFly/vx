package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type Cookies struct{}

func (c *Cookies) Name() string        { return "cookies" }
func (c *Cookies) Description() string { return "Cookie security flags analysis" }

func (c *Cookies) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	resp, _, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var findings []engine.Finding

	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return findings, nil
	}

	for _, raw := range setCookies {
		name := parseCookieName(raw)
		lower := strings.ToLower(raw)

		isSession := isSessionCookie(name)

		// HttpOnly check
		if !strings.Contains(lower, "httponly") {
			sev := engine.SevLow
			if isSession {
				sev = engine.SevHigh
			}
			findings = append(findings, engine.Finding{
				Module:      c.Name(),
				Severity:    sev,
				Title:       fmt.Sprintf("Cookie '%s' missing HttpOnly flag", name),
				Description: "Cookie can be accessed via JavaScript, enabling theft via XSS",
				Evidence:    truncate(raw, 120),
				CWE:         "CWE-1004",
				Remediation: "Add the HttpOnly flag to prevent client-side script access",
			})
		}

		// Secure check
		if !strings.Contains(lower, "secure") {
			sev := engine.SevLow
			if isSession {
				sev = engine.SevHigh
			}
			findings = append(findings, engine.Finding{
				Module:      c.Name(),
				Severity:    sev,
				Title:       fmt.Sprintf("Cookie '%s' missing Secure flag", name),
				Description: "Cookie can be sent over unencrypted HTTP connections",
				Evidence:    truncate(raw, 120),
				CWE:         "CWE-614",
				Remediation: "Add the Secure flag to ensure cookie is only sent over HTTPS",
			})
		}

		// SameSite check
		if !strings.Contains(lower, "samesite") {
			sev := engine.SevLow
			if isSession {
				sev = engine.SevMedium
			}
			findings = append(findings, engine.Finding{
				Module:      c.Name(),
				Severity:    sev,
				Title:       fmt.Sprintf("Cookie '%s' missing SameSite attribute", name),
				Description: "Cookie may be sent in cross-site requests, enabling CSRF attacks",
				Evidence:    truncate(raw, 120),
				CWE:         "CWE-1275",
				Remediation: "Add SameSite=Lax or SameSite=Strict attribute",
			})
		}

		// SameSite=None without Secure
		if strings.Contains(lower, "samesite=none") && !strings.Contains(lower, "secure") {
			findings = append(findings, engine.Finding{
				Module:      c.Name(),
				Severity:    engine.SevMedium,
				Title:       fmt.Sprintf("Cookie '%s' has SameSite=None without Secure", name),
				Description: "SameSite=None requires the Secure flag; browsers will reject this cookie",
				Evidence:    truncate(raw, 120),
				CWE:         "CWE-1275",
			})
		}
	}

	return findings, nil
}

func parseCookieName(raw string) string {
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return "unknown"
}

func isSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	sessionNames := []string{"phpsessid", "jsessionid", "session", "sess", "sid", "asp.net_sessionid", "connect.sid"}
	for _, s := range sessionNames {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
