package local

import (
	"bytes"
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

const osvAPIURL = "https://api.osv.dev/v1/query"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// osvQuery is the request body for the OSV.dev API.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvResponse is the response from the OSV.dev API.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string   `json:"aliases"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (d *Deps) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	var findings []engine.Finding

	// JavaScript / TypeScript
	if HasLanguage(cfg, "javascript") || HasLanguage(cfg, "typescript") {
		f, err := d.checkNPM(cfg)
		if err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [!] deps: npm check error: %v\n", err)
		}
		findings = append(findings, f...)
	}

	// PHP
	if HasLanguage(cfg, "php") {
		f, err := d.checkComposer(cfg)
		if err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [!] deps: composer check error: %v\n", err)
		}
		findings = append(findings, f...)
	}

	// Go
	if HasLanguage(cfg, "go") {
		f, err := d.checkGo(cfg)
		if err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [!] deps: go check error: %v\n", err)
		}
		findings = append(findings, f...)
	}

	// Python
	if HasLanguage(cfg, "python") {
		f, err := d.checkPython(cfg)
		if err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [!] deps: python check error: %v\n", err)
		}
		findings = append(findings, f...)
	}

	// Rust
	if HasLanguage(cfg, "rust") {
		f, err := d.checkRust(cfg)
		if err != nil && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [!] deps: rust check error: %v\n", err)
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

	return findings, nil
}

// checkNPM reads package.json and queries OSV.dev for each dependency.
func (d *Deps) checkNPM(cfg *AuditConfig) ([]engine.Finding, error) {
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

	var findings []engine.Finding
	allDeps := mergeMaps(pkg.Dependencies, pkg.DevDependencies)

	for name, version := range allDeps {
		version = cleanVersion(version)
		vulns, err := queryOSV(name, version, "npm")
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] deps: OSV query failed for %s: %v\n", name, err)
			}
			continue
		}
		for _, v := range vulns {
			findings = append(findings, vulnToFinding(name, version, v))
		}
	}

	return findings, nil
}

// checkComposer reads composer.lock and queries OSV.dev.
func (d *Deps) checkComposer(cfg *AuditConfig) ([]engine.Finding, error) {
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

	var findings []engine.Finding
	for _, pkg := range lock.Packages {
		version := cleanVersion(pkg.Version)
		vulns, err := queryOSV(pkg.Name, version, "Packagist")
		if err != nil {
			continue
		}
		for _, v := range vulns {
			findings = append(findings, vulnToFinding(pkg.Name, version, v))
		}
	}

	return findings, nil
}

// checkGo reads go.sum and queries OSV.dev.
func (d *Deps) checkGo(cfg *AuditConfig) ([]engine.Finding, error) {
	sumPath := filepath.Join(cfg.Path, "go.sum")
	data, err := os.ReadFile(sumPath)
	if err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var findings []engine.Finding

	for _, line := range strings.Split(string(data), "\n") {
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

		vulns, err := queryOSV(name, version, "Go")
		if err != nil {
			continue
		}
		for _, v := range vulns {
			findings = append(findings, vulnToFinding(name, version, v))
		}
	}

	return findings, nil
}

// checkPython reads requirements.txt and queries OSV.dev.
func (d *Deps) checkPython(cfg *AuditConfig) ([]engine.Finding, error) {
	reqPath := filepath.Join(cfg.Path, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return nil, nil
	}

	var findings []engine.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		name, version := parsePythonDep(line)
		if name == "" || version == "" {
			continue
		}

		vulns, err := queryOSV(name, version, "PyPI")
		if err != nil {
			continue
		}
		for _, v := range vulns {
			findings = append(findings, vulnToFinding(name, version, v))
		}
	}

	return findings, nil
}

// checkRust reads Cargo.lock and queries OSV.dev.
func (d *Deps) checkRust(cfg *AuditConfig) ([]engine.Finding, error) {
	lockPath := filepath.Join(cfg.Path, "Cargo.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, nil
	}

	var findings []engine.Finding
	// Simple TOML parsing for Cargo.lock [[package]] entries
	var currentName, currentVersion string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if currentName != "" && currentVersion != "" {
				vulns, err := queryOSV(currentName, currentVersion, "crates.io")
				if err == nil {
					for _, v := range vulns {
						findings = append(findings, vulnToFinding(currentName, currentVersion, v))
					}
				}
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
	// Process last package
	if currentName != "" && currentVersion != "" {
		vulns, err := queryOSV(currentName, currentVersion, "crates.io")
		if err == nil {
			for _, v := range vulns {
				findings = append(findings, vulnToFinding(currentName, currentVersion, v))
			}
		}
	}

	return findings, nil
}

// queryOSV queries the OSV.dev API for vulnerabilities.
func queryOSV(name, version, ecosystem string) ([]osvVuln, error) {
	query := osvQuery{
		Package: osvPackage{
			Name:      name,
			Ecosystem: ecosystem,
		},
		Version: version,
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Post(osvAPIURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result osvResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return result.Vulns, nil
}

// vulnToFinding converts an OSV vulnerability to an engine.Finding.
func vulnToFinding(pkgName, version string, vuln osvVuln) engine.Finding {
	sev := engine.SevMedium // default
	cvss := 5.0

	// Try to extract severity from vuln data
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" {
			// Parse CVSS score from vector string or score
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
	// If it's a raw number
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err == nil && score >= 0 && score <= 10 {
		return score
	}
	// Default
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
