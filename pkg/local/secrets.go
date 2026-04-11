package local

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// Secrets detects hardcoded secrets, API keys, and high-entropy strings in source files.
type Secrets struct{}

func (s *Secrets) Name() string        { return "secrets" }
func (s *Secrets) Description() string { return "Detect hardcoded secrets, API keys, and tokens" }

// secretPattern defines a regex pattern with metadata.
type secretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity engine.Severity
	CWE      string
}

var secretPatterns = []secretPattern{
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`(?:^|[^a-zA-Z0-9])(?:AKIA[0-9A-Z]{16})(?:[^a-zA-Z0-9]|$)`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "Stripe Secret Key",
		Pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "Stripe Publishable Key",
		Pattern:  regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
		Severity: engine.SevMedium,
		CWE:      "CWE-798",
	},
	{
		Name:     "GitHub Personal Access Token",
		Pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36,}`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "GitHub OAuth Token",
		Pattern:  regexp.MustCompile(`gho_[0-9a-zA-Z]{36,}`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "GitHub App Token",
		Pattern:  regexp.MustCompile(`(?:ghu|ghs|ghr)_[0-9a-zA-Z]{36,}`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`),
		Severity: engine.SevCritical,
		CWE:      "CWE-321",
	},
	{
		Name:     "Generic Password Assignment",
		Pattern:  regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|auth_token)\s*[:=]\s*["']([^"']{8,})["']`),
		Severity: engine.SevHigh,
		CWE:      "CWE-798",
	},
	{
		Name:     "Database URL with Credentials",
		Pattern:  regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s"']+`),
		Severity: engine.SevCritical,
		CWE:      "CWE-798",
	},
	{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`),
		Severity: engine.SevHigh,
		CWE:      "CWE-798",
	},
	{
		Name:     "Base64 Encoded Secret (long)",
		Pattern:  regexp.MustCompile(`(?i)(?:secret|key|token|password)\s*[:=]\s*["'](?:[A-Za-z0-9+/]{40,}={0,2})["']`),
		Severity: engine.SevMedium,
		CWE:      "CWE-798",
	},
	{
		Name:     "Slack Webhook",
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		Severity: engine.SevHigh,
		CWE:      "CWE-798",
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: engine.SevHigh,
		CWE:      "CWE-798",
	},
}

// highEntropyPattern matches quoted strings that might be secrets.
var highEntropyPattern = regexp.MustCompile(`["']([A-Za-z0-9+/=_-]{16,})["']`)

func (s *Secrets) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	ignore := ReadVxIgnore(cfg.Path)

	// Scan all common source file extensions
	extensions := []string{
		".go", ".php", ".js", ".ts", ".jsx", ".tsx",
		".py", ".rb", ".java", ".rs", ".yaml", ".yml",
		".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
		".sh", ".bash", ".zsh", ".env",
	}

	files, err := WalkFiles(cfg.Path, ignore, extensions)
	if err != nil {
		return nil, fmt.Errorf("walking files: %w", err)
	}

	var findings []engine.Finding

	for _, file := range files {
		fileFindings, err := s.scanFile(file, cfg)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] secrets: error reading %s: %v\n", file, err)
			}
			continue
		}
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

func (s *Secrets) scanFile(path string, cfg *AuditConfig) ([]engine.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	isTest := IsTestFile(path)

	var findings []engine.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments (basic heuristic)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Check known patterns
		for _, sp := range secretPatterns {
			if sp.Pattern.MatchString(line) {
				sev := sp.Severity
				if isTest {
					// Reduce severity for test files
					if sev > engine.SevLow {
						sev = engine.SevLow
					}
				}

				relPath := relativeToRoot(path, cfg.Path)
				findings = append(findings, engine.Finding{
					Module:      "secrets",
					Severity:    sev,
					Title:       fmt.Sprintf("%s detected", sp.Name),
					Description: fmt.Sprintf("Found in %s at line %d", relPath, lineNum),
					Evidence:    truncateLine(line, 120),
					Remediation: "Move secrets to environment variables or a secret manager. Rotate the exposed credential immediately.",
					CWE:         sp.CWE,
					CVSS:        severityToCVSS(sev),
				})
			}
		}

		// High-entropy string detection
		matches := highEntropyPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			candidate := match[1]
			if len(candidate) < 16 {
				continue
			}

			entropy := ShannonEntropy(candidate)
			if entropy > 4.5 {
				// Skip common false positives
				if looksLikeHash(candidate) || looksLikeEncoding(candidate) {
					continue
				}

				sev := engine.SevMedium
				if isTest {
					sev = engine.SevInfo
				}

				relPath := relativeToRoot(path, cfg.Path)
				findings = append(findings, engine.Finding{
					Module:      "secrets",
					Severity:    sev,
					Title:       "High-entropy string (possible secret)",
					Description: fmt.Sprintf("Found in %s at line %d (entropy: %.2f)", relPath, lineNum, entropy),
					Evidence:    truncateLine(line, 120),
					Remediation: "Review this string. If it is a secret, move it to environment variables.",
					CWE:         "CWE-798",
					CVSS:        4.0,
				})
			}
		}
	}

	return findings, scanner.Err()
}

func relativeToRoot(path, root string) string {
	rel, err := os.Getwd()
	_ = rel
	if r, err := strings.CutPrefix(path, root); err {
		return strings.TrimPrefix(r, string(os.PathSeparator))
	}
	_ = err
	return path
}

func truncateLine(line string, maxLen int) string {
	line = strings.TrimSpace(line)
	if len(line) > maxLen {
		return line[:maxLen] + "..."
	}
	return line
}

func severityToCVSS(sev engine.Severity) float64 {
	switch sev {
	case engine.SevCritical:
		return 9.0
	case engine.SevHigh:
		return 7.5
	case engine.SevMedium:
		return 5.0
	case engine.SevLow:
		return 2.0
	default:
		return 0.0
	}
}

// looksLikeHash returns true for hex strings that are likely file hashes.
func looksLikeHash(s string) bool {
	if len(s) != 32 && len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// looksLikeEncoding returns true for strings that are likely base64-encoded non-secret data.
func looksLikeEncoding(s string) bool {
	// Very long strings are likely data blobs, not secrets
	return len(s) > 256
}
