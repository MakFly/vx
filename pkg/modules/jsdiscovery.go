package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/MakFly/vx/pkg/engine"
)

// JSDiscovery discovers API endpoints by analysing JavaScript bundles.
type JSDiscovery struct{}

func (j *JSDiscovery) Name() string        { return "jsdiscovery" }
func (j *JSDiscovery) Description() string { return "API endpoint discovery from JavaScript bundles" }

const (
	maxBundles   = 20
	maxBundleLen = 5 * 1024 * 1024 // 5 MB
	maxProbe     = 30
	semSize      = 5
)

// skippedDomains are third-party script hosts we ignore.
var skippedDomains = []string{
	"google-analytics.com",
	"googletagmanager.com",
	"googleapis.com",
	"gstatic.com",
	"facebook.net",
	"facebook.com",
	"fbcdn.net",
	"doubleclick.net",
	"hotjar.com",
	"crisp.chat",
	"intercom.io",
	"sentry.io",
	"stripe.com",
	"cloudflare.com",
	"cloudflareinsights.com",
	"twitter.com",
	"linkedin.com",
	"pinterest.com",
	"youtube.com",
	"recaptcha.net",
	"hcaptcha.com",
}

var (
	reScriptSrc = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

	// Endpoint patterns inside JS bundles
	reAPIPath     = regexp.MustCompile(`/api/[a-zA-Z0-9/_-]+`)
	reVersionPath = regexp.MustCompile(`/v[0-9]+/[a-zA-Z0-9/_-]+`)
	reFetchCall   = regexp.MustCompile(`fetch\(["'](\/[^"']+)["']`)
	reAxiosCall   = regexp.MustCompile(`axios\.\w+\(["'](\/[^"']+)["']`)
	reAPILiteral  = regexp.MustCompile(`["'](\/(?:api|graphql|rest|v[0-9])[^"']*?)["']`)
	reWebSocket   = regexp.MustCompile(`wss?://[^"'\s]+`)

	// Sensitive data patterns in API responses
	reSensitive = regexp.MustCompile(`(?i)"(email|token|password|secret|access_token|refresh_token|api_key|private_key|ssn|credit_card)"`)

	// Admin/internal path indicators
	reAdminPath = regexp.MustCompile(`(?i)/(?:admin|internal|debug|_internal|management|backoffice)/`)

	// Static asset extensions to skip
	reStaticExt = regexp.MustCompile(`(?i)\.(png|jpg|jpeg|gif|svg|ico|webp|css|woff2?|ttf|eot|map)(\?|$)`)
)

type endpoint struct {
	Path     string
	Kind     string // "internal", "external", "websocket"
	Source   string // which bundle it came from
	External bool
}

func (j *JSDiscovery) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	host := extractHost(cfg.TargetURL)

	// Fetch homepage HTML
	_, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("homepage fetch failed: %w", err)
	}
	html := string(body)

	// Step 1: extract JS bundle URLs from HTML
	bundleURLs := j.extractBundleURLs(html, cfg.TargetURL, host)

	if len(bundleURLs) == 0 {
		return nil, nil
	}

	// Step 2: download bundles concurrently and extract endpoints
	endpoints := j.downloadAndExtract(client, bundleURLs, host, cfg.UserAgent)

	if len(endpoints) == 0 {
		return nil, nil
	}

	var findings []engine.Finding

	// Separate by kind
	var internal, external, websockets, adminPaths []endpoint
	for _, ep := range endpoints {
		switch ep.Kind {
		case "websocket":
			websockets = append(websockets, ep)
		case "external":
			external = append(external, ep)
		case "internal":
			if reAdminPath.MatchString(ep.Path) {
				adminPaths = append(adminPaths, ep)
			}
			internal = append(internal, ep)
		}
	}

	// Summary finding
	var evidenceLines []string
	for _, ep := range endpoints {
		evidenceLines = append(evidenceLines, fmt.Sprintf("[%s] %s", ep.Kind, ep.Path))
	}
	findings = append(findings, engine.Finding{
		Module:      j.Name(),
		Severity:    engine.SevInfo,
		Title:       fmt.Sprintf("%d API endpoints discovered from JS bundles", len(endpoints)),
		Description: fmt.Sprintf("Extracted from %d JavaScript bundles on the target", len(bundleURLs)),
		Evidence:    truncate(strings.Join(evidenceLines, "\n"), 2000),
	})

	// WebSocket endpoints
	for _, ep := range websockets {
		findings = append(findings, engine.Finding{
			Module:      j.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("WebSocket endpoint found: %s", truncate(ep.Path, 80)),
			Description: "WebSocket URL discovered in JavaScript bundle",
			Evidence:    ep.Path,
		})
	}

	// External API URLs
	for _, ep := range external {
		findings = append(findings, engine.Finding{
			Module:      j.Name(),
			Severity:    engine.SevLow,
			Title:       "Hardcoded API URL to external service",
			Description: "JavaScript bundle contains a hardcoded URL to an external API",
			Evidence:    truncate(ep.Path, 200),
		})
	}

	// Admin/internal paths in JS
	for _, ep := range adminPaths {
		findings = append(findings, engine.Finding{
			Module:      j.Name(),
			Severity:    engine.SevMedium,
			Title:       fmt.Sprintf("Internal/admin API path found in JS: %s", truncate(ep.Path, 60)),
			Description: "Admin or internal API path exposed in client-side JavaScript bundle",
			CWE:         "CWE-200",
			Evidence:    ep.Path,
			Remediation: "Remove internal/admin API references from client-side JavaScript bundles",
		})
	}

	// Step 4: probe internal endpoints
	findings = append(findings, j.probeEndpoints(client, cfg, internal)...)

	return findings, nil
}

// extractBundleURLs parses <script src="..."> from HTML and returns absolute URLs for same-origin scripts.
func (j *JSDiscovery) extractBundleURLs(html, baseURL, host string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	matches := reScriptSrc.FindAllStringSubmatch(html, -1)
	seen := make(map[string]bool)
	var urls []string

	for _, m := range matches {
		src := m[1]

		// Resolve relative URLs
		parsed, err := url.Parse(src)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(parsed)
		abs := resolved.String()

		// Skip duplicates
		if seen[abs] {
			continue
		}
		seen[abs] = true

		// Skip third-party tracking/analytics
		resolvedHost := strings.ToLower(resolved.Hostname())
		if j.isSkippedDomain(resolvedHost) {
			continue
		}

		// Only include same-origin or relative scripts
		if resolvedHost != "" && resolvedHost != strings.ToLower(host) {
			// Allow known CDN patterns that serve the target's own bundles
			if !j.isOwnCDN(resolvedHost, host) {
				continue
			}
		}

		// Skip non-JS files
		path := strings.ToLower(resolved.Path)
		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".mjs") &&
			!strings.Contains(path, ".js?") && !strings.Contains(abs, ".js?") &&
			!strings.Contains(path, "chunk") && !strings.Contains(path, "bundle") {
			// Allow paths that look like bundled JS even without .js extension
			if !strings.Contains(path, "_next/") && !strings.Contains(path, "_nuxt/") &&
				!strings.Contains(path, "/assets/") {
				continue
			}
		}

		urls = append(urls, abs)
		if len(urls) >= maxBundles {
			break
		}
	}

	return urls
}

// isSkippedDomain checks if a hostname belongs to a known third-party service.
func (j *JSDiscovery) isSkippedDomain(host string) bool {
	for _, d := range skippedDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// isOwnCDN detects CDN subdomains serving the target's own assets.
func (j *JSDiscovery) isOwnCDN(cdnHost, targetHost string) bool {
	// cdn.example.com serving assets for example.com
	domain := strings.TrimPrefix(targetHost, "www.")
	if strings.HasSuffix(cdnHost, "."+domain) {
		return true
	}
	// Common CDN patterns: assets.example.com, static.example.com
	prefixes := []string{"cdn.", "assets.", "static.", "js.", "scripts."}
	for _, p := range prefixes {
		if cdnHost == p+domain {
			return true
		}
	}
	return false
}

// downloadAndExtract fetches JS bundles concurrently and extracts endpoints.
func (j *JSDiscovery) downloadAndExtract(client *http.Client, urls []string, host, ua string) []endpoint {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, semSize)
		all []endpoint
	)

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(bundleURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			eps := j.fetchAndParse(client, bundleURL, host, ua)
			if len(eps) > 0 {
				mu.Lock()
				all = append(all, eps...)
				mu.Unlock()
			}
		}(u)
	}

	wg.Wait()

	// Deduplicate
	return dedupeEndpoints(all)
}

// fetchAndParse downloads a single JS bundle and extracts endpoints.
func (j *JSDiscovery) fetchAndParse(client *http.Client, bundleURL, host, ua string) []endpoint {
	req, err := http.NewRequest("GET", bundleURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleLen))
	if err != nil {
		return nil
	}

	js := string(body)
	var endpoints []endpoint

	// Build dynamic regex for same-domain full URLs
	escapedHost := regexp.QuoteMeta(host)
	reFullURL := regexp.MustCompile(`https?://[^"'\s]*` + escapedHost + `[^"'\s]*`)

	// Extract all patterns
	extractPaths := func(re *regexp.Regexp, group int) {
		for _, m := range re.FindAllStringSubmatch(js, -1) {
			path := m[group]
			if reStaticExt.MatchString(path) {
				continue
			}
			endpoints = append(endpoints, endpoint{
				Path:   path,
				Kind:   "internal",
				Source: bundleURL,
			})
		}
	}

	// API paths: /api/...
	for _, m := range reAPIPath.FindAllString(js, -1) {
		if reStaticExt.MatchString(m) {
			continue
		}
		endpoints = append(endpoints, endpoint{Path: m, Kind: "internal", Source: bundleURL})
	}

	// Versioned paths: /v1/...
	for _, m := range reVersionPath.FindAllString(js, -1) {
		if reStaticExt.MatchString(m) {
			continue
		}
		endpoints = append(endpoints, endpoint{Path: m, Kind: "internal", Source: bundleURL})
	}

	// fetch() calls
	extractPaths(reFetchCall, 1)

	// axios calls
	extractPaths(reAxiosCall, 1)

	// String literals that look like API paths
	extractPaths(reAPILiteral, 1)

	// Full URLs with same domain
	for _, m := range reFullURL.FindAllString(js, -1) {
		if reStaticExt.MatchString(m) {
			continue
		}
		// Parse to get just the path for internal classification
		parsed, err := url.Parse(m)
		if err != nil {
			continue
		}
		ep := endpoint{Path: parsed.Path, Kind: "internal", Source: bundleURL}
		if parsed.RawQuery != "" {
			ep.Path = parsed.Path + "?" + parsed.RawQuery
		}
		endpoints = append(endpoints, ep)
	}

	// Full URLs to external domains
	reAnyFullURL := regexp.MustCompile(`https?://([^"'\s/]+)([^"'\s]*)`)
	for _, m := range reAnyFullURL.FindAllStringSubmatch(js, -1) {
		urlHost := strings.ToLower(m[1])
		fullPath := m[0]

		// Skip same domain, static assets, and known tracking domains
		if strings.Contains(urlHost, strings.TrimPrefix(host, "www.")) {
			continue
		}
		if j.isSkippedDomain(urlHost) {
			continue
		}
		if reStaticExt.MatchString(fullPath) {
			continue
		}
		// Only report if it looks like an API URL
		pathPart := m[2]
		if strings.Contains(pathPart, "/api") || strings.Contains(pathPart, "/v1") ||
			strings.Contains(pathPart, "/v2") || strings.Contains(pathPart, "/graphql") ||
			strings.Contains(pathPart, "/rest") {
			endpoints = append(endpoints, endpoint{
				Path:     fullPath,
				Kind:     "external",
				Source:   bundleURL,
				External: true,
			})
		}
	}

	// WebSocket URLs
	for _, m := range reWebSocket.FindAllString(js, -1) {
		endpoints = append(endpoints, endpoint{
			Path:   m,
			Kind:   "websocket",
			Source: bundleURL,
		})
	}

	return endpoints
}

// dedupeEndpoints removes duplicate paths, keeping the first occurrence.
func dedupeEndpoints(eps []endpoint) []endpoint {
	seen := make(map[string]bool)
	var result []endpoint
	for _, ep := range eps {
		key := ep.Kind + "|" + ep.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, ep)
	}
	// Sort for deterministic output
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Path < result[j].Path
	})
	return result
}

// probeEndpoints sends GET requests to internal endpoints and reports accessible ones.
func (j *JSDiscovery) probeEndpoints(client *http.Client, cfg *engine.Config, internal []endpoint) []engine.Finding {
	var findings []engine.Finding

	// Limit probing
	toProbe := internal
	if len(toProbe) > maxProbe {
		toProbe = toProbe[:maxProbe]
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, semSize)
	)

	for _, ep := range toProbe {
		wg.Add(1)
		sem <- struct{}{}

		go func(ep endpoint) {
			defer wg.Done()
			defer func() { <-sem }()

			targetURL := strings.TrimRight(cfg.TargetURL, "/") + ep.Path
			result := DoRequest(client, "GET", targetURL, cfg.UserAgent)

			// Skip non-responses
			if result.Code == 0 || result.Code == 404 || result.Code == 405 {
				return
			}

			// Skip SPA catch-all
			if IsSPACatchAll(result.Body) {
				return
			}

			// Check if it's a real API response (JSON/XML)
			ct := strings.ToLower(result.ContentType)
			isAPI := strings.Contains(ct, "application/json") ||
				strings.Contains(ct, "application/xml") ||
				strings.Contains(ct, "text/xml")

			if !isAPI {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			// Check for sensitive data patterns
			if reSensitive.MatchString(result.Body) {
				findings = append(findings, engine.Finding{
					Module:      j.Name(),
					Severity:    engine.SevMedium,
					Title:       fmt.Sprintf("Unauthenticated API endpoint exposes data: %s", truncate(ep.Path, 60)),
					Description: fmt.Sprintf("API endpoint returns %s data without authentication (HTTP %d)", ct, result.Code),
					Evidence:    truncate(result.Body, 500),
					CWE:         "CWE-306",
					Remediation: "Require authentication for API endpoints that return sensitive data",
				})
				return
			}

			// Accessible API endpoint (non-sensitive) — informational
			if result.Code >= 200 && result.Code < 300 {
				findings = append(findings, engine.Finding{
					Module:      j.Name(),
					Severity:    engine.SevInfo,
					Title:       fmt.Sprintf("Accessible API endpoint: %s (HTTP %d)", truncate(ep.Path, 60), result.Code),
					Description: "API endpoint discovered from JS bundle responds with data",
					Evidence:    fmt.Sprintf("GET %s -> %d %s", ep.Path, result.Code, ct),
				})
			}
		}(ep)
	}

	wg.Wait()
	return findings
}
