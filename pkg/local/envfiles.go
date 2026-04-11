package local

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// EnvFiles audits environment files for security issues.
type EnvFiles struct{}

func (e *EnvFiles) Name() string        { return "env-files" }
func (e *EnvFiles) Description() string { return "Audit .env files for security and exposure risks" }

func (e *EnvFiles) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	var findings []engine.Finding

	// Check for .env file existence
	envPath := filepath.Join(cfg.Path, ".env")
	if _, err := os.Stat(envPath); err == nil {
		// .env exists — check if it's in .gitignore
		if !isInGitignore(cfg.Path, ".env") {
			findings = append(findings, engine.Finding{
				Module:      "env-files",
				Severity:    engine.SevCritical,
				Title:       ".env file not in .gitignore",
				Description: "The .env file exists but is not listed in .gitignore, risking secret exposure.",
				Remediation: "Add .env to .gitignore immediately. If already committed, remove from git history.",
				CWE:         "CWE-200",
				CVSS:        9.0,
			})
		}

		// Check if .env is tracked by git
		if isTrackedByGit(cfg.Path, ".env") {
			findings = append(findings, engine.Finding{
				Module:      "env-files",
				Severity:    engine.SevCritical,
				Title:       ".env file is committed to git",
				Description: "The .env file is tracked by git. Secrets in it are part of the repository history.",
				Evidence:    ".env found in git ls-files output",
				Remediation: "Remove .env from git tracking: git rm --cached .env && add to .gitignore. Consider rotating all secrets.",
				CWE:         "CWE-200",
				CVSS:        9.0,
			})
		}
	}

	// Check .env.example for real secrets
	examplePath := filepath.Join(cfg.Path, ".env.example")
	if _, err := os.Stat(examplePath); err == nil {
		exampleFindings := checkEnvExampleForSecrets(examplePath)
		findings = append(findings, exampleFindings...)
	}

	// Check for sensitive env file variants
	sensitiveFiles := []string{
		".env.local",
		".env.production",
		".env.production.local",
		".env.staging",
		".env.development.local",
	}

	for _, name := range sensitiveFiles {
		fullPath := filepath.Join(cfg.Path, name)
		if _, err := os.Stat(fullPath); err == nil {
			if isTrackedByGit(cfg.Path, name) {
				findings = append(findings, engine.Finding{
					Module:      "env-files",
					Severity:    engine.SevHigh,
					Title:       fmt.Sprintf("%s is committed to git", name),
					Description: fmt.Sprintf("Environment file %s is tracked by git and may contain secrets.", name),
					Remediation: fmt.Sprintf("Remove %s from git tracking and add to .gitignore.", name),
					CWE:         "CWE-200",
					CVSS:        7.5,
				})
			}

			if !isInGitignore(cfg.Path, name) {
				findings = append(findings, engine.Finding{
					Module:      "env-files",
					Severity:    engine.SevMedium,
					Title:       fmt.Sprintf("%s not in .gitignore", name),
					Description: fmt.Sprintf("Environment file %s exists but is not gitignored.", name),
					Remediation: fmt.Sprintf("Add %s to .gitignore.", name),
					CWE:         "CWE-200",
					CVSS:        5.0,
				})
			}
		}
	}

	return findings, nil
}

// isInGitignore checks if a file pattern is covered by .gitignore.
func isInGitignore(root, filename string) bool {
	gitignorePath := filepath.Join(root, ".gitignore")
	f, err := os.Open(gitignorePath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Simple matching: exact match, prefix with /, or glob
		if line == filename || line == "/"+filename {
			return true
		}
		// Match patterns like .env* or *.local
		if matched, _ := filepath.Match(line, filename); matched {
			return true
		}
	}
	return false
}

// isTrackedByGit checks if a file is tracked by git using git ls-files.
func isTrackedByGit(root, filename string) bool {
	cmd := exec.Command("git", "ls-files", "--error-unmatch", filename)
	cmd.Dir = root
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// checkEnvExampleForSecrets scans .env.example for values with high entropy.
func checkEnvExampleForSecrets(path string) []engine.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []engine.Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}

		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		// Skip placeholder values
		if value == "" || isPlaceholder(value) {
			continue
		}

		if len(value) > 8 && ShannonEntropy(value) > 4.0 {
			findings = append(findings, engine.Finding{
				Module:      "env-files",
				Severity:    engine.SevHigh,
				Title:       "Real secret in .env.example",
				Description: fmt.Sprintf("Variable %s at line %d has a high-entropy value that looks like a real secret.", parts[0], lineNum),
				Evidence:    fmt.Sprintf("%s=<redacted> (entropy: %.2f)", parts[0], ShannonEntropy(value)),
				Remediation: "Replace real values in .env.example with placeholder descriptions.",
				CWE:         "CWE-200",
				CVSS:        7.0,
			})
		}
	}

	return findings
}

// isPlaceholder returns true for common placeholder values in example env files.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	placeholders := []string{
		"your_", "change_me", "replace_", "xxx", "todo",
		"example", "placeholder", "changeme", "secret",
		"password", "null", "none", "empty", "fill_",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Single words or very short values are likely placeholders
	if len(value) <= 4 {
		return true
	}
	return false
}
