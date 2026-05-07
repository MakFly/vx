package local

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

// Deps scans project dependencies for known vulnerabilities via OSV.dev.
type Deps struct{}

func (d *Deps) Name() string        { return "dependencies" }
func (d *Deps) Description() string { return "Check dependencies for known vulnerabilities (OSV.dev)" }

const (
	osvBatchAPIURL = "https://api.osv.dev/v1/querybatch"
	// maxResponseBytes caps the OSV response body to prevent memory exhaustion.
	maxResponseBytes = 1 << 20 // 1 MiB
	// osvRetryMax is the maximum number of attempts for a single OSV request.
	osvRetryMax = 3
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// osvBatchQuery is the request body for the OSV.dev /v1/querybatch endpoint.
type osvBatchQuery struct {
	Queries []osvQuery `json:"queries"`
}

// osvQuery is a single query within a batch.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchResponse is the response from /v1/querybatch.
type osvBatchResponse struct {
	Results []osvResponse `json:"results"`
}

// osvResponse is the per-query result.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// depEntry holds a (name, version, ecosystem) triple for batch queries.
type depEntry struct {
	name      string
	version   string
	ecosystem string
}

func (d *Deps) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	ctx := context.Background()
	var findings []engine.Finding
	var scanErrors []string

	// JavaScript / TypeScript
	if HasLanguage(cfg, "javascript") || HasLanguage(cfg, "typescript") {
		f, err := d.checkNPM(ctx, cfg)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("npm: %v", err))
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: npm check error: %v\n", err)
			}
		}
		findings = append(findings, f...)
	}

	// PHP
	if HasLanguage(cfg, "php") {
		f, err := d.checkComposer(ctx, cfg)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("composer: %v", err))
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: composer check error: %v\n", err)
			}
		}
		findings = append(findings, f...)
	}

	// Go
	if HasLanguage(cfg, "go") {
		f, err := d.checkGo(ctx, cfg)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("go: %v", err))
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: go check error: %v\n", err)
			}
		}
		findings = append(findings, f...)
	}

	// Python
	if HasLanguage(cfg, "python") {
		f, err := d.checkPython(ctx, cfg)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("python: %v", err))
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: python check error: %v\n", err)
			}
		}
		findings = append(findings, f...)
	}

	// Rust
	if HasLanguage(cfg, "rust") {
		f, err := d.checkRust(ctx, cfg)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("rust: %v", err))
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: rust check error: %v\n", err)
			}
		}
		findings = append(findings, f...)
	}

	// Java — detection only
	if HasLanguage(cfg, "java") {
		pomPath := filepath.Join(cfg.Path, "pom.xml")
		if _, err := os.Stat(pomPath); err == nil {
			findings = append(findings, engine.Finding{
				Module:      "dependencies",
				Severity:    engine.SevInfo,
				Title:       "Java project detected (pom.xml)",
				Description: "Automated vulnerability checking for Java/Maven is limited. Consider using OWASP Dependency-Check.",
				Remediation: "Run: mvn org.owasp:dependency-check-maven:check",
				CWE:         "CWE-1104",
			})
		}
	}

	if len(scanErrors) > 0 {
		return findings, fmt.Errorf("dependency scan incomplete: %s", strings.Join(scanErrors, "; "))
	}
	return findings, nil
}

// checkNPM reads package.json and queries OSV.dev for each dependency.
func (d *Deps) checkNPM(ctx context.Context, cfg *AuditConfig) ([]engine.Finding, error) {
	pkgPath := filepath.Join(cfg.Path, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, nil // no package.json, skip
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	allDeps := mergeMaps(pkg.Dependencies, pkg.DevDependencies)
	entries := make([]depEntry, 0, len(allDeps))
	for name, version := range allDeps {
		entries = append(entries, depEntry{
			name:      name,
			version:   cleanVersion(version),
			ecosystem: "npm",
		})
	}

	return queryOSVBatch(ctx, entries)
}

// checkComposer reads composer.lock and queries OSV.dev.
func (d *Deps) checkComposer(ctx context.Context, cfg *AuditConfig) ([]engine.Finding, error) {
	lockPath := filepath.Join(cfg.Path, "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, nil
	}

	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	entries := make([]depEntry, 0, len(lock.Packages))
	for _, pkg := range lock.Packages {
		entries = append(entries, depEntry{
			name:      pkg.Name,
			version:   cleanVersion(pkg.Version),
			ecosystem: "Packagist",
		})
	}

	return queryOSVBatch(ctx, entries)
}

// checkGo reads go.sum line by line and queries OSV.dev.
func (d *Deps) checkGo(ctx context.Context, cfg *AuditConfig) ([]engine.Finding, error) {
	sumPath := filepath.Join(cfg.Path, "go.sum")
	f, err := os.Open(sumPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var entries []depEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		version := strings.TrimSuffix(parts[1], "/go.mod")
		version = strings.TrimPrefix(version, "v")

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		entries = append(entries, depEntry{
			name:      name,
			version:   version,
			ecosystem: "Go",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}

	return queryOSVBatch(ctx, entries)
}

// checkPython reads requirements.txt line by line and queries OSV.dev.
func (d *Deps) checkPython(ctx context.Context, cfg *AuditConfig) ([]engine.Finding, error) {
	reqPath := filepath.Join(cfg.Path, "requirements.txt")
	f, err := os.Open(reqPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var entries []depEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name, version := parsePythonDep(line)
		if name == "" || version == "" {
			continue
		}
		entries = append(entries, depEntry{
			name:      name,
			version:   version,
			ecosystem: "PyPI",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read requirements.txt: %w", err)
	}

	return queryOSVBatch(ctx, entries)
}

// checkRust reads Cargo.lock line by line and queries OSV.dev.
func (d *Deps) checkRust(ctx context.Context, cfg *AuditConfig) ([]engine.Finding, error) {
	lockPath := filepath.Join(cfg.Path, "Cargo.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var entries []depEntry
	var currentName, currentVersion string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if currentName != "" && currentVersion != "" {
				entries = append(entries, depEntry{
					name:      currentName,
					version:   currentVersion,
					ecosystem: "crates.io",
				})
			}
			currentName = ""
			currentVersion = ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Cargo.lock: %w", err)
	}
	// Process last package
	if currentName != "" && currentVersion != "" {
		entries = append(entries, depEntry{
			name:      currentName,
			version:   currentVersion,
			ecosystem: "crates.io",
		})
	}

	return queryOSVBatch(ctx, entries)
}

// queryOSVBatch queries the OSV.dev /v1/querybatch endpoint for a list of
// dependencies in a single HTTP call, with retry/backoff on transient errors.
func queryOSVBatch(ctx context.Context, entries []depEntry) ([]engine.Finding, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	queries := make([]osvQuery, len(entries))
	for i, e := range entries {
		queries[i] = osvQuery{
			Package: osvPackage{Name: e.name, Ecosystem: e.ecosystem},
			Version: e.version,
		}
	}

	reqBody, err := json.Marshal(osvBatchQuery{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal OSV batch query: %w", err)
	}

	var batchResp osvBatchResponse
	if err := doOSVRequestWithRetry(ctx, reqBody, &batchResp); err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for i, res := range batchResp.Results {
		if i >= len(entries) {
			break
		}
		e := entries[i]
		for _, v := range res.Vulns {
			findings = append(findings, vulnToFinding(e.name, e.version, v))
		}
	}

	return findings, nil
}

// doOSVRequestWithRetry performs the HTTP POST to the OSV batch endpoint with
// exponential backoff on transient status codes (429, 500, 502, 503, 504).
func doOSVRequestWithRetry(ctx context.Context, body []byte, dest interface{}) error {
	var lastErr error
	for attempt := 0; attempt < osvRetryMax; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s (capped)
			wait := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchAPIURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create OSV request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("OSV API unreachable: %w", err)
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// success path
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			resp.Body.Close()
			lastErr = fmt.Errorf("OSV API returned status %d", resp.StatusCode)
			continue
		default:
			resp.Body.Close()
			return fmt.Errorf("OSV API returned status %d", resp.StatusCode)
		}

		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(dest); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decode OSV response: %w", err)
		}
		resp.Body.Close()
		return nil
	}

	return fmt.Errorf("OSV API failed after %d attempts: %w", osvRetryMax, lastErr)
}

// vulnToFinding converts an OSV vulnerability to an engine.Finding.
func vulnToFinding(pkgName, version string, vuln osvVuln) engine.Finding {
	sev := engine.SevMedium // default
	cvss := 5.0

	// Try to extract severity from vuln data
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" {
			cvss = parseCVSSScore(s.Score)
			sev = cvssToSeverity(cvss)
			break
		}
	}

	// Build CVE alias string
	var cveID string
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}
	if cveID == "" {
		cveID = vuln.ID
	}

	summary := vuln.Summary
	if summary == "" {
		summary = "Vulnerability found"
	}

	return engine.Finding{
		Module:      "dependencies",
		Severity:    sev,
		Title:       fmt.Sprintf("Vulnerable dependency: %s@%s", pkgName, version),
		Description: fmt.Sprintf("[%s] %s", cveID, summary),
		Evidence:    fmt.Sprintf("Affected: %s version %s", pkgName, version),
		Remediation: "Update the dependency to a patched version.",
		CWE:         "CWE-1104",
		CVSS:        cvss,
	}
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Remove npm-style prefixes
	v = strings.TrimLeft(v, "^~>=<!")
	v = strings.TrimPrefix(v, "v")
	// Take only the first version in a range
	if idx := strings.Index(v, " "); idx > 0 {
		v = v[:idx]
	}
	return v
}

var pythonDepRegex = regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*[=~!><]+\s*([0-9][0-9a-zA-Z._-]*)`)

func parsePythonDep(line string) (string, string) {
	m := pythonDepRegex.FindStringSubmatch(line)
	if len(m) >= 3 {
		return m[1], m[2]
	}
	return "", ""
}

func mergeMaps(a, b map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range a {
		result[k] = v
	}
	for k, v := range b {
		result[k] = v
	}
	return result
}

func parseCVSSScore(s string) float64 {
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err == nil && score >= 0 && score <= 10 {
		return score
	}
	return 5.0
}

func cvssToSeverity(cvss float64) engine.Severity {
	switch {
	case cvss >= 9.0:
		return engine.SevCritical
	case cvss >= 7.0:
		return engine.SevHigh
	case cvss >= 4.0:
		return engine.SevMedium
	case cvss >= 0.1:
		return engine.SevLow
	default:
		return engine.SevInfo
	}
}
