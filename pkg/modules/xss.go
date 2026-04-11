package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type XSS struct{}

func (x *XSS) Name() string        { return "xss" }
func (x *XSS) Description() string { return "Reflected XSS detection via form inputs and URL parameters" }

func (x *XSS) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	base := strings.TrimRight(cfg.TargetURL, "/")

	var findings []engine.Finding

	// Phase 1: discover forms and search endpoints
	_, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	html := string(body)

	// Find search endpoints
	searchPaths := x.discoverSearchEndpoints(html, base)

	// Phase 2: test each endpoint for reflected XSS
	seen := make(map[string]bool)
	for _, endpoint := range searchPaths {
		epFindings := x.testReflectedXSS(client, endpoint, cfg)
		for _, f := range epFindings {
			key := f.Title + "|" + f.CWE
			if !seen[key] {
				seen[key] = true
				findings = append(findings, f)
			}
		}
	}

	// Phase 3: test common parameter-based XSS
	findings = append(findings, x.testParamXSS(client, base, cfg)...)

	// Phase 4: check for XSS protection mechanisms
	findings = append(findings, x.checkXSSProtections(html, cfg)...)

	return findings, nil
}

type searchEndpoint struct {
	url   string
	param string
	name  string
}

func (x *XSS) discoverSearchEndpoints(html string, base string) []searchEndpoint {
	var endpoints []searchEndpoint
	seen := make(map[string]bool)

	addUnique := func(ep searchEndpoint) {
		key := ep.url + "|" + ep.param
		if !seen[key] {
			seen[key] = true
			endpoints = append(endpoints, ep)
		}
	}

	// Look for search forms — match action + its own inputs
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
			addUnique(searchEndpoint{url: action, param: paramName, name: "form-" + paramName})
		}
	}

	// Common search URL patterns
	commonSearch := []searchEndpoint{
		{url: base + "/recherche", param: "search_query", name: "search (PrestaShop)"},
		{url: base + "/search", param: "q", name: "search-q"},
		{url: base + "/search", param: "s", name: "search-s"},
	}
	for _, ep := range commonSearch {
		addUnique(ep)
	}

	return endpoints
}

func (x *XSS) testReflectedXSS(client *http.Client, ep searchEndpoint, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Unique marker to track reflection
	marker := "vx7r4c3m4rk3r"

	// Test 1: simple reflection
	testURL := fmt.Sprintf("%s?%s=%s", ep.url, ep.param, marker)
	_, body, err := doGet(client, testURL, cfg.UserAgent)
	if err != nil {
		return findings
	}
	html := string(body)

	reflections := strings.Count(html, marker)
	if reflections == 0 {
		return findings // Input not reflected at all
	}

	// Analyze reflection contexts
	contexts := x.analyzeReflectionContexts(html, marker)

	// Test 2: HTML tag injection
	payloads := []struct {
		name    string
		payload string
		check   func(string) bool
		sev     engine.Severity
	}{
		{
			name:    "HTML tag injection",
			payload: "<img src=x onerror=vxtest>",
			check: func(html string) bool {
				return strings.Contains(html, "<img src=x onerror=vxtest>")
			},
			sev: engine.SevHigh,
		},
		{
			name:    "SVG onload injection",
			payload: "<svg onload=vxtest>",
			check: func(html string) bool {
				return strings.Contains(html, "<svg onload=vxtest>")
			},
			sev: engine.SevHigh,
		},
		{
			name:    "Script tag injection",
			payload: "<script>vxtest</script>",
			check: func(html string) bool {
				return strings.Contains(html, "<script>vxtest</script>")
			},
			sev: engine.SevCritical,
		},
		{
			name:    "Attribute breakout (double quote)",
			payload: `" onfocus=vxtest autofocus="`,
			check: func(body string) bool {
				// Search for all occurrences of onfocus=vxtest
				needle := "onfocus=vxtest"
				remaining := body
				for {
					idx := strings.Index(remaining, needle)
					if idx == -1 {
						return false
					}

					absIdx := len(body) - len(remaining) + idx
					before := body[max(0, absIdx-200):absIdx]

					// Skip: preceded by &quot; — means the quote was HTML-encoded, not a real breakout
					if strings.HasSuffix(strings.TrimRight(before, " "), "&quot;") {
						remaining = remaining[idx+len(needle):]
						continue
					}

					// Skip: inside a <script> block (JS context, not HTML attribute)
					lastScript := strings.LastIndex(before, "<script")
					if lastScript != -1 && !strings.Contains(before[lastScript:], "</script>") {
						remaining = remaining[idx+len(needle):]
						continue
					}

					// Confirm: must be inside an HTML tag (between < and >)
					lastOpen := strings.LastIndex(before, "<")
					lastClose := strings.LastIndex(before, ">")
					if lastOpen == -1 || lastClose > lastOpen {
						// Not inside a tag — the match is in text content, not an attribute
						remaining = remaining[idx+len(needle):]
						continue
					}

					// We found onfocus=vxtest unencoded inside an HTML tag attribute context
					return true
				}
			},
			sev: engine.SevHigh,
		},
		{
			name:    "Script context breakout",
			payload: `</script><svg onload=vxtest>`,
			check: func(html string) bool {
				return strings.Contains(html, `</script><svg onload=vxtest>`)
			},
			sev: engine.SevCritical,
		},
	}

	for _, p := range payloads {
		encoded := url.QueryEscape(p.payload)
		testURL := fmt.Sprintf("%s?%s=%s", ep.url, ep.param, encoded)
		_, testBody, err := doGet(client, testURL, cfg.UserAgent)
		if err != nil {
			continue
		}
		testHTML := string(testBody)

		// SPA catch-all pages (Next.js, React, etc.) return 200 for any route
		// and re-render the homepage — any "match" is a false positive.
		if IsSPACatchAll(testHTML) {
			continue
		}

		if p.check(testHTML) {
			// Determine context
			context := x.getInjectionContext(testHTML, p.payload)

			findings = append(findings, engine.Finding{
				Module:      x.Name(),
				Severity:    p.sev,
				Title:       fmt.Sprintf("Reflected XSS via %s on %s=%s", p.name, ep.name, ep.param),
				Description: fmt.Sprintf("Unencoded %s reflected in %s context at %s", p.name, context, ep.url),
				Evidence:    fmt.Sprintf("Param: %s | Payload: %s | Context: %s", ep.param, p.payload, context),
				CWE:         "CWE-79",
				Remediation: "HTML-encode all user input before output. Implement Content-Security-Policy.",
				CVSS:        6.1,
			})
		}
	}

	// Test 3: check for unencoded reflection in JS context (dataLayer, JSON, etc.)
	jsPayload := `","vxtest":"injected`
	jsEncoded := url.QueryEscape(jsPayload)
	jsTestURL := fmt.Sprintf("%s?%s=%s", ep.url, ep.param, jsEncoded)
	_, jsBody, err := doGet(client, jsTestURL, cfg.UserAgent)
	if err == nil {
		jsHTML := string(jsBody)
		// Check if JSON injection succeeded (quotes not encoded in JS context)
		if strings.Contains(jsHTML, `"vxtest":"injected"`) {
			findings = append(findings, engine.Finding{
				Module:      x.Name(),
				Severity:    engine.SevHigh,
				Title:       fmt.Sprintf("JSON injection in JavaScript context via %s", ep.param),
				Description: "User input injected into JavaScript object without proper JSON encoding",
				Evidence:    fmt.Sprintf("Param: %s | JSON key injection successful", ep.param),
				CWE:         "CWE-79",
				Remediation: "Use json_encode() with JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT flags",
				CVSS:        7.1,
			})
		}
	}

	// Report reflection even if not directly exploitable
	if len(findings) == 0 && reflections > 0 {
		findings = append(findings, engine.Finding{
			Module:      x.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("Input reflected %d times at %s (properly encoded)", reflections, ep.name),
			Description: fmt.Sprintf("Parameter %s is reflected but HTML-encoded in all contexts", ep.param),
			Evidence:    fmt.Sprintf("Contexts: %s", strings.Join(contexts, ", ")),
		})
	}

	return findings
}

func (x *XSS) testParamXSS(client *http.Client, base string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Test error pages for reflection
	errorPaths := []string{
		base + "/404<img src=x onerror=vxtest>",
		base + "/%3Cscript%3Evxtest%3C/script%3E",
	}

	for _, path := range errorPaths {
		_, body, err := doGet(client, path, cfg.UserAgent)
		if err != nil {
			continue
		}
		html := string(body)
		// SPA frameworks return catch-all pages for unknown routes — skip them
		if IsSPACatchAll(html) {
			continue
		}
		if strings.Contains(html, "<img src=x onerror=vxtest>") || strings.Contains(html, "<script>vxtest</script>") {
			findings = append(findings, engine.Finding{
				Module:      x.Name(),
				Severity:    engine.SevHigh,
				Title:       "XSS in error page via URL path",
				Description: "The 404 error page reflects the URL path without encoding",
				Evidence:    "URL path reflected unencoded in error page HTML",
				CWE:         "CWE-79",
				Remediation: "HTML-encode the requested URL in error page templates",
				CVSS:        6.1,
			})
			break
		}
	}

	return findings
}

func (x *XSS) checkXSSProtections(html string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Check if Content-Security-Policy would block inline scripts
	// (already checked in headers module, but we add XSS-specific context)

	// Check for unsafe patterns in JS
	unsafePatterns := []struct {
		pattern *regexp.Regexp
		name    string
		desc    string
	}{
		{
			pattern: regexp.MustCompile(`(?i)\.innerHTML\s*=\s*[^"']`),
			name:    "innerHTML assignment detected",
			desc:    "Direct innerHTML assignment may enable DOM-based XSS if user input reaches it",
		},
		{
			pattern: regexp.MustCompile(`(?i)document\.write\(`),
			name:    "document.write() usage detected",
			desc:    "document.write() can enable DOM-based XSS",
		},
		{
			pattern: regexp.MustCompile(`(?i)eval\([^)]*(?:location|document|window)`),
			name:    "eval() with DOM source detected",
			desc:    "eval() with DOM-based input source is a high-risk XSS sink",
		},
	}

	for _, p := range unsafePatterns {
		matches := p.pattern.FindAllString(html, 3)
		if len(matches) > 0 {
			findings = append(findings, engine.Finding{
				Module:      x.Name(),
				Severity:    engine.SevLow,
				Title:       p.name,
				Description: p.desc,
				Evidence:    truncate(matches[0], 100),
				CWE:         "CWE-79",
			})
		}
	}

	// Check for unencoded user data in JavaScript contexts
	// Look for patterns like dataLayer with unencoded HTML
	dlPattern := regexp.MustCompile(`(?i)dataLayer\.push\(\{[^}]*"[^"]*<[a-z]`)
	if dlPattern.MatchString(html) {
		findings = append(findings, engine.Finding{
			Module:      x.Name(),
			Severity:    engine.SevMedium,
			Title:       "Unencoded HTML in dataLayer JavaScript object",
			Description: "HTML tags appear unencoded inside a dataLayer.push() call. While in a JSON string (not directly exploitable), any JS code reading this value and inserting it into DOM without encoding creates an XSS sink.",
			Evidence:    "HTML tags found inside dataLayer JSON values",
			CWE:         "CWE-79",
			Remediation: "HTML-encode values before inserting into dataLayer, or use textContent instead of innerHTML when reading dataLayer values",
			CVSS:        4.7,
		})
	}

	return findings
}

func (x *XSS) analyzeReflectionContexts(html string, marker string) []string {
	var contexts []string
	seen := make(map[string]bool)

	lines := strings.Split(html, "\n")
	for _, line := range lines {
		if !strings.Contains(line, marker) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		var ctx string
		switch {
		case strings.Contains(trimmed, "value=") || strings.Contains(trimmed, "content="):
			ctx = "HTML-attribute"
		case strings.Contains(trimmed, "dataLayer") || strings.Contains(trimmed, "var ") || strings.Contains(trimmed, "let "):
			ctx = "JavaScript"
		case strings.Contains(trimmed, "<meta"):
			ctx = "meta-tag"
		case strings.Contains(trimmed, "href="):
			ctx = "URL-attribute"
		default:
			ctx = "HTML-body"
		}
		if !seen[ctx] {
			seen[ctx] = true
			contexts = append(contexts, ctx)
		}
	}
	return contexts
}

func (x *XSS) getInjectionContext(html string, payload string) string {
	idx := strings.Index(html, payload)
	if idx == -1 {
		return "unknown"
	}

	// Get surrounding context (200 chars before)
	start := idx - 200
	if start < 0 {
		start = 0
	}
	before := html[start:idx]

	switch {
	case strings.Contains(before, "<script") && !strings.Contains(before[strings.LastIndex(before, "<script"):], "</script>"):
		return "script-tag"
	case strings.Contains(before, "value=\"") || strings.Contains(before, "value='"):
		return "input-attribute"
	case strings.Contains(before, "href=\"") || strings.Contains(before, "href='"):
		return "href-attribute"
	default:
		return "HTML-body"
	}
}
