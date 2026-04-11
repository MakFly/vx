package modules

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// OpenRedirect detects open redirect vulnerabilities by testing common
// redirect parameters with evil-domain payloads and inspecting Location headers.
type OpenRedirect struct{}

func (o *OpenRedirect) Name() string        { return "redirect" }
func (o *OpenRedirect) Description() string { return "Open redirect vulnerability detection" }

var redirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri",
	"return", "return_to", "next", "goto", "target",
	"dest", "destination", "rurl", "continue", "callback",
}

var redirectPages = []string{
	"", "/login", "/connexion", "/auth",
	"/logout", "/deconnexion", "/callback",
}

var redirectPayloads = []string{
	"https://evil.com",
	"//evil.com",
	`/\evil.com`,
	"https://evil.com%00.legitimate.com",
	"javascript:alert(1)",
}

func (o *OpenRedirect) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newNoRedirectClient(cfg)
	base := strings.TrimRight(cfg.TargetURL, "/")

	var findings []engine.Finding
	seen := make(map[string]bool)

	for _, page := range redirectPages {
		pageURL := base + page
		for _, param := range redirectParams {
			for _, payload := range redirectPayloads {
				encoded := url.QueryEscape(payload)
				testURL := fmt.Sprintf("%s?%s=%s", pageURL, param, encoded)

				resp, body, err := doGet(client, testURL, cfg.UserAgent)
				if err != nil {
					continue
				}

				// Check 3xx Location header
				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					location := resp.Header.Get("Location")
					if location != "" && o.isEvilRedirect(location, payload) {
						key := fmt.Sprintf("%s|%s", page, param)
						if seen[key] {
							continue
						}
						seen[key] = true

						findings = append(findings, engine.Finding{
							Module:      o.Name(),
							Severity:    engine.SevHigh,
							Title:       fmt.Sprintf("Open redirect via %s parameter on %s", param, page),
							Description: fmt.Sprintf("Server returns %d redirect to attacker-controlled URL when %s=%s", resp.StatusCode, param, payload),
							Evidence:    fmt.Sprintf("Location: %s (from %s)", truncate(location, 200), testURL),
							CWE:         "CWE-601",
							Remediation: "Validate redirect URLs against an allowlist of trusted domains. Use relative paths only or verify the host before redirecting.",
							CVSS:        6.1,
						})
						break // one payload is enough per param+page
					}
				}

				// Check meta refresh in response body
				bodyStr := string(body)
				if IsSPACatchAll(bodyStr) {
					continue
				}
				if o.hasMetaRefreshEvil(bodyStr) {
					key := fmt.Sprintf("meta|%s|%s", page, param)
					if seen[key] {
						continue
					}
					seen[key] = true

					findings = append(findings, engine.Finding{
						Module:      o.Name(),
						Severity:    engine.SevHigh,
						Title:       fmt.Sprintf("Open redirect via meta refresh on %s (param %s)", page, param),
						Description: fmt.Sprintf("Response contains <meta http-equiv=\"refresh\"> pointing to attacker-controlled URL"),
						Evidence:    fmt.Sprintf("Payload: %s on %s", payload, testURL),
						CWE:         "CWE-601",
						Remediation: "Do not use user-controlled values in meta refresh URLs. Validate redirect targets server-side.",
						CVSS:        6.1,
					})
					break
				}
			}
		}
	}

	return findings, nil
}

// isEvilRedirect checks whether a Location header value actually redirects to the evil domain.
// It only checks the HOST of the redirect target — not query parameters or fragments.
func (o *OpenRedirect) isEvilRedirect(location, payload string) bool {
	// Parse the Location URL to extract the actual redirect target host
	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Host)

	// The redirect target host must be evil.com (not just appearing in a query param)
	if host == "evil.com" || strings.HasSuffix(host, ".evil.com") {
		return true
	}

	// Protocol-relative redirect: //evil.com
	if parsed.Host == "" && strings.HasPrefix(location, "//") {
		afterSlash := strings.TrimPrefix(location, "//")
		if strings.HasPrefix(strings.ToLower(afterSlash), "evil.com") {
			return true
		}
	}

	// javascript: redirect
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(location)), "javascript:") {
		return true
	}

	return false
}

// hasMetaRefreshEvil checks for <meta http-equiv="refresh" content="...evil.com...">
func (o *OpenRedirect) hasMetaRefreshEvil(body string) bool {
	lower := strings.ToLower(body)
	idx := 0
	for {
		pos := strings.Index(lower[idx:], `<meta`)
		if pos == -1 {
			return false
		}
		idx += pos
		end := strings.Index(lower[idx:], ">")
		if end == -1 {
			return false
		}
		tag := lower[idx : idx+end+1]
		if strings.Contains(tag, `http-equiv`) && strings.Contains(tag, `refresh`) && strings.Contains(tag, "evil.com") {
			return true
		}
		idx += end + 1
	}
}
