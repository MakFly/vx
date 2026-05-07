package modules

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type Webservice struct{}

func (w *Webservice) Name() string        { return "webservice" }
func (w *Webservice) Description() string { return "API/webservice discovery and security testing" }

func (w *Webservice) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	base := strings.TrimRight(cfg.TargetURL, "/")

	var findings []engine.Finding

	// PrestaShop webservice
	findings = append(findings, w.testPrestaShop(client, base, cfg)...)

	// Common API endpoints
	findings = append(findings, w.testCommonAPIs(client, base, cfg)...)

	// Module AJAX endpoints (PrestaShop-specific)
	findings = append(findings, w.testModuleEndpoints(client, base, cfg)...)

	return findings, nil
}

func (w *Webservice) testPrestaShop(client *http.Client, base string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Test /api/ without auth
	apiEndpoints := []string{"/api/", "/api", "/webservice/"}
	for _, ep := range apiEndpoints {
		r := w.probeDetailed(client, base+ep, cfg.UserAgent)
		if r.Code == 401 {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    engine.SevMedium,
				Title:       fmt.Sprintf("API endpoint active: %s (HTTP 401)", ep),
				Description: "API endpoint exists and requires authentication. If not needed, it should be disabled.",
				Evidence:    fmt.Sprintf("GET %s → 401 Unauthorized", ep),
				CWE:         "CWE-16",
				Remediation: "Disable the webservice if not used, or restrict by IP whitelist",
			})

			// Check error message format for info disclosure
			if strings.Contains(r.Body, "Invalid authentication key format") {
				findings = append(findings, engine.Finding{
					Module:      w.Name(),
					Severity:    engine.SevLow,
					Title:       "API leaks key format validation details",
					Description: "Error messages reveal the expected authentication key format",
					Evidence:    "Error code 18: Invalid authentication key format",
					CWE:         "CWE-209",
					Remediation: "Return a generic 401 error without format details",
				})
			}
			break // Only report once
		}
		if IsRealAPIResponse(r) {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    engine.SevCritical,
				Title:       fmt.Sprintf("API endpoint %s accessible without authentication!", ep),
				Description: "The webservice API is accessible without any authentication",
				Evidence:    fmt.Sprintf("GET %s → 200 OK (Content-Type: %s)", ep, r.ContentType),
				CWE:         "CWE-306",
				Remediation: "Immediately restrict API access with authentication keys and IP whitelisting",
			})
			break
		}
	}

	// Test with common default keys (PrestaShop uses 32-char hex)
	defaultKeys := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"00000000000000000000000000000000",
		"11111111111111111111111111111111",
		"abcdefabcdefabcdefabcdefabcdefab",
		"ffffffffffffffffffffffffffffffff",
	}

	for _, key := range defaultKeys {
		code, body := w.probeWithAuth(client, base+"/api/", key, cfg.UserAgent)
		// Verify it's a real API response, not a framework catch-all
		if code == 200 && !strings.Contains(body, "_next/static") && !strings.Contains(body, "<!DOCTYPE html>") {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    engine.SevCritical,
				Title:       "API accessible with default/weak key!",
				Description: fmt.Sprintf("Webservice API authenticated with trivial key: %s...", key[:8]),
				Evidence:    fmt.Sprintf("Key %s → HTTP 200", key),
				CWE:         "CWE-798",
				Remediation: "Change the API key immediately and use a strong random key",
			})
			break
		}
		// Detect different error for valid-format but wrong key
		if strings.Contains(body, "not active") || strings.Contains(body, "No permission") {
			// Key format accepted but not valid — this is expected, info only
			if len(findings) == 0 || !containsTitle(findings, "API differentiates key format errors") {
				findings = append(findings, engine.Finding{
					Module:      w.Name(),
					Severity:    engine.SevLow,
					Title:       "API differentiates key format errors from auth errors",
					Description: "Different error codes for invalid format (18) vs valid format but wrong key (20/21). Enables key format enumeration.",
					Evidence:    "Code 18 = bad format, Code 20/21 = valid format but wrong key",
					CWE:         "CWE-209",
					Remediation: "Return identical errors regardless of key format validity",
				})
			}
		}
	}

	// Test resource enumeration
	resources := []string{"products", "customers", "orders", "carts", "addresses", "manufacturers", "categories", "configurations", "employees"}
	var accessibleResources []string

	for _, res := range resources {
		r := w.probeDetailed(client, base+"/api/"+res, cfg.UserAgent)
		if IsRealAPIResponse(r) {
			accessibleResources = append(accessibleResources, res)
		}
	}

	if len(accessibleResources) > 0 {
		findings = append(findings, engine.Finding{
			Module:      w.Name(),
			Severity:    engine.SevCritical,
			Title:       fmt.Sprintf("%d API resources accessible without auth", len(accessibleResources)),
			Description: "API resources are accessible without authentication",
			Evidence:    strings.Join(accessibleResources, ", "),
			CWE:         "CWE-306",
			Remediation: "Restrict all API resources with proper authentication",
		})
	}

	return findings
}

func (w *Webservice) testCommonAPIs(client *http.Client, base string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	apis := []struct {
		path string
		name string
	}{
		{"/graphql", "GraphQL"},
		{"/graphiql", "GraphiQL IDE"},
		{"/_graphql", "GraphQL (alt)"},
		{"/api/swagger", "Swagger UI"},
		{"/swagger.json", "Swagger JSON"},
		{"/api-docs", "API Documentation"},
		{"/openapi.json", "OpenAPI spec"},
		{"/v1/", "REST API v1"},
		{"/v2/", "REST API v2"},
		{"/rest/", "REST API"},
		{"/.well-known/openid-configuration", "OpenID Configuration"},
		{"/wp-json/wp/v2/users", "WordPress User API"},
	}

	for _, api := range apis {
		r := w.probeDetailed(client, base+api.path, cfg.UserAgent)
		if IsRealAPIResponse(r) {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    engine.SevMedium,
				Title:       fmt.Sprintf("%s endpoint accessible: %s", api.name, api.path),
				Description: fmt.Sprintf("%s is publicly accessible (Content-Type: %s)", api.name, r.ContentType),
				Evidence:    fmt.Sprintf("GET %s → %d", api.path, r.Code),
				CWE:         "CWE-16",
				Remediation: "Restrict access or add authentication if this endpoint should not be public",
			})
		}
	}

	return findings
}

func (w *Webservice) testModuleEndpoints(client *http.Client, base string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// PrestaShop module AJAX endpoints
	modules := []struct {
		path     string
		name     string
		severity engine.Severity
	}{
		{"/module/psgdpr/FrontAjaxGdpr", "GDPR data export module", engine.SevMedium},
		{"/module/mdrecurrentorder/ajax", "Recurring orders module", engine.SevLow},
		{"/module/ps_emailsubscription/subscription", "Email subscription", engine.SevLow},
	}

	for _, mod := range modules {
		r := w.probeDetailed(client, base+mod.path, cfg.UserAgent)
		if IsRealAPIResponse(r) {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    mod.severity,
				Title:       fmt.Sprintf("Module endpoint accessible: %s", mod.name),
				Description: fmt.Sprintf("%s responds to unauthenticated GET at %s", mod.name, mod.path),
				Evidence:    fmt.Sprintf("GET %s → 200", mod.path),
				CWE:         "CWE-284",
			})
		}
		if r.Code == 500 {
			findings = append(findings, engine.Finding{
				Module:      w.Name(),
				Severity:    engine.SevLow,
				Title:       fmt.Sprintf("Module endpoint error: %s returns 500", mod.path),
				Description: "Internal server error may leak stack traces if debug mode is enabled",
				Evidence:    fmt.Sprintf("GET %s → 500", mod.path),
				CWE:         "CWE-209",
			})
		}
	}

	return findings
}


func (w *Webservice) probeDetailed(client *http.Client, url string, ua string) ProbeResult {
	return DoRequest(client, "GET", url, ua)
}

func (w *Webservice) probeWithAuth(client *http.Client, url string, key string, ua string) (int, string) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", ua)
	req.SetBasicAuth(key, "")

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body)
}

func containsTitle(findings []engine.Finding, title string) bool {
	for _, f := range findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

// Unused but available for future XML parsing of webservice responses
type psError struct {
	XMLName xml.Name `xml:"prestashop"`
	Errors  []struct {
		Code    string `xml:"code"`
		Message string `xml:"message"`
	} `xml:"errors>error"`
}
