package modules

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type HTTPMethods struct{}

func (h *HTTPMethods) Name() string        { return "httpmethods" }
func (h *HTTPMethods) Description() string { return "HTTP methods testing (OPTIONS, TRACE, PUT, DELETE)" }

func (h *HTTPMethods) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	var findings []engine.Finding

	// Test OPTIONS first to see what the server advertises
	findings = append(findings, h.testOptions(client, cfg)...)

	// Test individual dangerous methods
	findings = append(findings, h.testTrace(client, cfg)...)
	findings = append(findings, h.testWriteMethods(client, cfg)...)

	return findings, nil
}

func (h *HTTPMethods) testOptions(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	req, err := http.NewRequest("OPTIONS", cfg.TargetURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if allow == "" {
		// Some servers use Access-Control-Allow-Methods for OPTIONS
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}

	if allow != "" {
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevInfo,
			Title:       "Server advertises allowed HTTP methods",
			Description: "OPTIONS response reveals which HTTP methods are supported",
			Evidence:    fmt.Sprintf("Allow: %s (HTTP %d)", allow, resp.StatusCode),
		})
	}

	return findings
}

func (h *HTTPMethods) testTrace(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	req, err := http.NewRequest("TRACE", cfg.TargetURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("X-Custom-Header", "vx-trace-test")

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	bodyStr := string(body)

	if resp.StatusCode == 200 {
		// A real TRACE response echoes the request in message/http content-type,
		// not as an HTML page. SPA catch-alls and generic HTML pages are NOT XST.
		ct := resp.Header.Get("Content-Type")
		isHTMLPage := strings.Contains(strings.ToLower(ct), "text/html") ||
			strings.Contains(bodyStr, "<!DOCTYPE") || strings.Contains(bodyStr, "<!doctype") ||
			IsSPACatchAll(bodyStr)

		// True TRACE echo: body contains the custom header we sent AND is not an HTML page
		if !isHTMLPage && strings.Contains(bodyStr, "vx-trace-test") {
			findings = append(findings, engine.Finding{
				Module:      h.Name(),
				Severity:    engine.SevHigh,
				Title:       "TRACE method enabled (Cross-Site Tracing)",
				Description: "The server responds to TRACE requests by echoing the request back, which can be exploited for Cross-Site Tracing (XST) to steal credentials and cookies",
				Evidence:    fmt.Sprintf("TRACE %s → HTTP %d, body echoes request headers", cfg.TargetURL, resp.StatusCode),
				CWE:         "CWE-693",
				CVSS:        5.3,
				Remediation: "Disable the TRACE HTTP method on the web server",
			})
		}
	}

	return findings
}

func (h *HTTPMethods) testWriteMethods(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	writeMethods := []struct {
		method string
		risk   string
	}{
		{"PUT", "allows file upload/overwrite on the server"},
		{"DELETE", "allows resource deletion on the server"},
	}

	for _, wm := range writeMethods {
		r := DoRequest(client, wm.method, cfg.TargetURL, cfg.UserAgent)
		if r.Code == 0 {
			continue
		}

		// Skip explicitly rejected methods
		if r.Code == 405 || r.Code == 501 || r.Code == 403 ||
			r.Code == 404 || r.Code == 301 || r.Code == 302 {
			continue
		}

		// For 2xx responses, check if this is a real API response or a SPA catch-all
		if r.Code >= 200 && r.Code < 300 {
			if IsSPACatchAll(r.Body) {
				findings = append(findings, engine.Finding{
					Module:      h.Name(),
					Severity:    engine.SevInfo,
					Title:       fmt.Sprintf("%s method returns 200 (SPA catch-all)", wm.method),
					Description: fmt.Sprintf("%s/%s returns 200 but response is a SPA catch-all page (not exploitable)", wm.method, wm.risk[:strings.Index(wm.risk, " ")]),
					Evidence:    fmt.Sprintf("%s %s → HTTP %d (SPA catch-all detected)", wm.method, cfg.TargetURL, r.Code),
				})
				continue
			}

			// text/html with a full HTML page is also likely a catch-all, not a real API
			ct := strings.ToLower(r.ContentType)
			if strings.Contains(ct, "text/html") &&
				(strings.Contains(r.Body, "<!DOCTYPE") || strings.Contains(r.Body, "<!doctype")) {
				findings = append(findings, engine.Finding{
					Module:      h.Name(),
					Severity:    engine.SevInfo,
					Title:       fmt.Sprintf("%s method returns 200 (HTML page, likely catch-all)", wm.method),
					Description: fmt.Sprintf("%s returns 200 with a full HTML page — likely a framework catch-all, not a real vulnerability", wm.method),
					Evidence:    fmt.Sprintf("%s %s → HTTP %d (Content-Type: %s)", wm.method, cfg.TargetURL, r.Code, r.ContentType),
				})
				continue
			}

			// Real API accepting PUT/DELETE — flag as HIGH
			findings = append(findings, engine.Finding{
				Module:      h.Name(),
				Severity:    engine.SevHigh,
				Title:       fmt.Sprintf("%s method not explicitly rejected", wm.method),
				Description: fmt.Sprintf("The server did not return 405/501 for %s requests — %s", wm.method, wm.risk),
				Evidence:    fmt.Sprintf("%s %s → HTTP %d (Content-Type: %s)", wm.method, cfg.TargetURL, r.Code, r.ContentType),
				CWE:         "CWE-749",
				Remediation: fmt.Sprintf("Disable or restrict the %s method if not required. Return 405 Method Not Allowed.", wm.method),
			})
			continue
		}

		// Non-2xx, non-rejected status codes — medium severity
		findings = append(findings, engine.Finding{
			Module:      h.Name(),
			Severity:    engine.SevMedium,
			Title:       fmt.Sprintf("%s method not explicitly rejected", wm.method),
			Description: fmt.Sprintf("The server did not return 405/501 for %s requests — %s", wm.method, wm.risk),
			Evidence:    fmt.Sprintf("%s %s → HTTP %d", wm.method, cfg.TargetURL, r.Code),
			CWE:         "CWE-749",
			Remediation: fmt.Sprintf("Disable or restrict the %s method if not required. Return 405 Method Not Allowed.", wm.method),
		})
	}

	return findings
}
