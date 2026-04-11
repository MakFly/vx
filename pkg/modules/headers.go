package modules

import (
	"fmt"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type Headers struct{}

func (h *Headers) Name() string        { return "headers" }
func (h *Headers) Description() string { return "Security headers analysis" }

func (h *Headers) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	resp, _, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var findings []engine.Finding

	// Required security headers
	required := []struct {
		header      string
		severity    engine.Severity
		cwe         string
		remediation string
	}{
		{
			header:      "Content-Security-Policy",
			severity:    engine.SevHigh,
			cwe:         "CWE-1021",
			remediation: "Add a Content-Security-Policy header to prevent XSS and injection attacks. Start with: default-src 'self'; script-src 'self'",
		},
		{
			header:      "X-Frame-Options",
			severity:    engine.SevMedium,
			cwe:         "CWE-1021",
			remediation: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
		},
		{
			header:      "X-Content-Type-Options",
			severity:    engine.SevMedium,
			cwe:         "CWE-16",
			remediation: "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing",
		},
		{
			header:      "Referrer-Policy",
			severity:    engine.SevLow,
			cwe:         "CWE-200",
			remediation: "Add Referrer-Policy: strict-origin-when-cross-origin",
		},
		{
			header:      "Permissions-Policy",
			severity:    engine.SevLow,
			cwe:         "CWE-16",
			remediation: "Add Permissions-Policy to restrict browser feature access (camera, microphone, geolocation, etc.)",
		},
	}

	for _, r := range required {
		val := resp.Header.Get(r.header)
		if val == "" {
			findings = append(findings, engine.Finding{
				Module:      h.Name(),
				Severity:    r.severity,
				Title:       fmt.Sprintf("Missing %s header", r.header),
				Description: fmt.Sprintf("The %s security header is not set", r.header),
				CWE:         r.cwe,
				Remediation: r.remediation,
			})
		}
	}

	// HSTS check
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevHigh,
			Title:       "Missing HSTS header",
			Description: "Strict-Transport-Security is not set, allowing protocol downgrade attacks",
			CWE:         "CWE-319",
			Remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		})
	} else {
		if !strings.Contains(hsts, "includeSubDomains") {
			findings = append(findings, engine.Finding{
				Module:      h.Name(),
				Severity:    engine.SevLow,
				Title:       "HSTS missing includeSubDomains",
				Description: "HSTS is set but without includeSubDomains directive",
				Evidence:    hsts,
				CWE:         "CWE-319",
				Remediation: "Add includeSubDomains to HSTS header",
			})
		}
		if !strings.Contains(hsts, "preload") {
			findings = append(findings, engine.Finding{
				Module:      h.Name(),
				Severity:    engine.SevInfo,
				Title:       "HSTS missing preload directive",
				Evidence:    hsts,
				CWE:         "CWE-319",
			})
		}
	}

	// Server header disclosure
	server := resp.Header.Get("Server")
	if server != "" {
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevLow,
			Title:       "Server header exposes technology",
			Description: fmt.Sprintf("Server header reveals: %s", server),
			Evidence:    server,
			CWE:         "CWE-200",
			Remediation: "Remove or obfuscate the Server header",
		})
	}

	// X-Powered-By disclosure
	xpb := resp.Header.Get("X-Powered-By")
	if xpb != "" {
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevLow,
			Title:       "X-Powered-By header exposes technology",
			Description: fmt.Sprintf("X-Powered-By reveals: %s", xpb),
			Evidence:    xpb,
			CWE:         "CWE-200",
			Remediation: "Remove the X-Powered-By header",
		})
	}

	// Cache control on main page
	cc := resp.Header.Get("Cache-Control")
	pragma := resp.Header.Get("Pragma")
	if cc == "" && pragma == "" {
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevInfo,
			Title:       "No cache control headers",
			Description: "Neither Cache-Control nor Pragma headers are set",
		})
	}

	return findings, nil
}
