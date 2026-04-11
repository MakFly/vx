package modules

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type CORS struct{}

func (c *CORS) Name() string        { return "cors" }
func (c *CORS) Description() string { return "CORS misconfiguration testing" }

func (c *CORS) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	var findings []engine.Finding

	// Test 1: Evil origin reflection
	findings = append(findings, c.testOriginReflection(client, cfg)...)

	// Test 2: Null origin
	findings = append(findings, c.testNullOrigin(client, cfg)...)

	// Test 3: Wildcard with credentials
	findings = append(findings, c.testWildcardCredentials(client, cfg)...)

	// Test 4: Dangerous methods
	findings = append(findings, c.testDangerousMethods(client, cfg)...)

	// Test 5: Subdomain matching bypass
	findings = append(findings, c.testSubdomainBypass(client, cfg)...)

	return findings, nil
}

func (c *CORS) sendCORSRequest(client *http.Client, targetURL, origin, ua string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Origin", origin)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp, nil
}

func (c *CORS) testOriginReflection(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	evilOrigin := "https://evil.com"
	resp, err := c.sendCORSRequest(client, cfg.TargetURL, evilOrigin, cfg.UserAgent)
	if err != nil {
		return findings
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == evilOrigin {
		sev := engine.SevHigh
		desc := "Server reflects arbitrary origins in Access-Control-Allow-Origin header"
		if strings.EqualFold(acac, "true") {
			sev = engine.SevCritical
			desc = "Server reflects arbitrary origins AND allows credentials — any site can make authenticated cross-origin requests"
		}
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    sev,
			Title:       "CORS origin reflection vulnerability",
			Description: desc,
			Evidence:    fmt.Sprintf("Origin: %s → ACAO: %s, ACAC: %s", evilOrigin, acao, acac),
			CWE:         "CWE-942",
			CVSS:        8.1,
			Remediation: "Validate the Origin header against an explicit allowlist. Never reflect arbitrary origins.",
		})
	}

	return findings
}

func (c *CORS) testNullOrigin(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	resp, err := c.sendCORSRequest(client, cfg.TargetURL, "null", cfg.UserAgent)
	if err != nil {
		return findings
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "null" {
		sev := engine.SevMedium
		desc := "Server allows the 'null' origin, which can be triggered via sandboxed iframes or data: URIs"
		if strings.EqualFold(acac, "true") {
			sev = engine.SevHigh
			desc += " — with credentials allowed, this enables cross-origin data theft"
		}
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    sev,
			Title:       "CORS allows null origin",
			Description: desc,
			Evidence:    fmt.Sprintf("Origin: null → ACAO: %s, ACAC: %s", acao, acac),
			CWE:         "CWE-942",
			CVSS:        6.5,
			Remediation: "Do not allow the 'null' origin in CORS configuration",
		})
	}

	return findings
}

func (c *CORS) testWildcardCredentials(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	resp, err := c.sendCORSRequest(client, cfg.TargetURL, "https://test.com", cfg.UserAgent)
	if err != nil {
		return findings
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	// Wildcard with credentials is a spec violation but some servers do it
	if acao == "*" && strings.EqualFold(acac, "true") {
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    engine.SevHigh,
			Title:       "CORS wildcard with credentials",
			Description: "Access-Control-Allow-Origin is '*' with Access-Control-Allow-Credentials: true. Browsers block this per spec, but it indicates a misconfiguration.",
			Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
			CWE:         "CWE-942",
			Remediation: "Replace wildcard '*' with explicit origin allowlist when credentials are needed",
		})
	}

	// Just wildcard is informational
	if acao == "*" && !strings.EqualFold(acac, "true") {
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    engine.SevInfo,
			Title:       "CORS allows all origins (wildcard)",
			Description: "Access-Control-Allow-Origin is set to '*'. This is acceptable for public APIs but may be too permissive for sensitive endpoints.",
			Evidence:    fmt.Sprintf("ACAO: %s", acao),
			CWE:         "CWE-942",
		})
	}

	return findings
}

func (c *CORS) testDangerousMethods(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	req, err := http.NewRequest("OPTIONS", cfg.TargetURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "PUT")

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	resp.Body.Close()

	methods := resp.Header.Get("Access-Control-Allow-Methods")
	if methods == "" {
		return findings
	}

	dangerous := []string{"PUT", "DELETE", "PATCH"}
	var found []string
	methodsUpper := strings.ToUpper(methods)
	for _, m := range dangerous {
		if strings.Contains(methodsUpper, m) {
			found = append(found, m)
		}
	}

	if len(found) > 0 {
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    engine.SevMedium,
			Title:       "CORS allows dangerous HTTP methods",
			Description: fmt.Sprintf("Preflight response allows potentially dangerous methods: %s", strings.Join(found, ", ")),
			Evidence:    fmt.Sprintf("Access-Control-Allow-Methods: %s", methods),
			CWE:         "CWE-942",
			Remediation: "Restrict allowed methods to only those needed (typically GET, POST)",
		})
	}

	return findings
}

func (c *CORS) testSubdomainBypass(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	host := extractHost(cfg.TargetURL)
	domain := strings.TrimPrefix(host, "www.")

	// Try a fake subdomain of the target domain
	fakeOrigin := fmt.Sprintf("https://evil.%s", domain)
	resp, err := c.sendCORSRequest(client, cfg.TargetURL, fakeOrigin, cfg.UserAgent)
	if err != nil {
		return findings
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == fakeOrigin {
		findings = append(findings, engine.Finding{
			Module:      c.Name(),
			Severity:    engine.SevHigh,
			Title:       "CORS allows arbitrary subdomains",
			Description: "Server trusts any subdomain of the target domain. If any subdomain is compromised (e.g. via XSS), it can make cross-origin requests.",
			Evidence:    fmt.Sprintf("Origin: %s → ACAO: %s", fakeOrigin, acao),
			CWE:         "CWE-942",
			CVSS:        7.1,
			Remediation: "Validate origins against an explicit allowlist rather than matching subdomains with a regex suffix",
		})
	}

	return findings
}
