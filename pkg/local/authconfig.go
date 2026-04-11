package local

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// AuthConfig audits authentication and framework security configuration.
type AuthConfig struct{}

func (a *AuthConfig) Name() string        { return "auth-config" }
func (a *AuthConfig) Description() string { return "Audit auth, CORS, and framework security config" }

func (a *AuthConfig) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	var findings []engine.Finding

	// Generic config checks
	findings = append(findings, a.checkCORSWildcard(cfg)...)
	findings = append(findings, a.checkDebugMode(cfg)...)

	// Framework-specific checks
	if HasLanguage(cfg, "typescript") || HasLanguage(cfg, "javascript") {
		findings = append(findings, a.checkNextJS(cfg)...)
		findings = append(findings, a.checkExpress(cfg)...)
	}

	if HasLanguage(cfg, "php") {
		findings = append(findings, a.checkSymfony(cfg)...)
		findings = append(findings, a.checkLaravel(cfg)...)
	}

	return findings, nil
}

// checkCORSWildcard scans configuration files for CORS wildcard origins.
func (a *AuthConfig) checkCORSWildcard(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding

	corsPattern := regexp.MustCompile(`(?i)(?:cors|origin|access-control-allow-origin)\s*[:=]\s*["'*]?\*["']?`)

	configFiles := findConfigFiles(cfg.Path)
	for _, file := range configFiles {
		lineFindings := scanFileForPattern(file, corsPattern, cfg.Path, engine.Finding{
			Module:      "auth-config",
			Severity:    engine.SevHigh,
			Title:       "CORS wildcard origin (*)",
			Description: "Access-Control-Allow-Origin set to * allows any origin to access the API.",
			Remediation: "Restrict CORS to specific trusted origins.",
			CWE:         "CWE-942",
			CVSS:        7.0,
		})
		findings = append(findings, lineFindings...)
	}

	return findings
}

// checkDebugMode scans for debug mode enabled in configuration.
func (a *AuthConfig) checkDebugMode(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding

	debugPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:APP_DEBUG|DEBUG)\s*=\s*(?:true|1|yes)`),
		regexp.MustCompile(`(?i)["']debug["']\s*[:=]\s*(?:true|1|True)`),
	}

	configFiles := findConfigFiles(cfg.Path)
	for _, file := range configFiles {
		// Skip .env.example
		if strings.HasSuffix(file, ".example") {
			continue
		}
		for _, pattern := range debugPatterns {
			lineFindings := scanFileForPattern(file, pattern, cfg.Path, engine.Finding{
				Module:      "auth-config",
				Severity:    engine.SevMedium,
				Title:       "Debug mode enabled",
				Description: "Debug mode may expose stack traces, internal paths, and sensitive data.",
				Remediation: "Disable debug mode in production (APP_DEBUG=false).",
				CWE:         "CWE-489",
				CVSS:        5.0,
			})
			findings = append(findings, lineFindings...)
		}
	}

	return findings
}

// checkNextJS checks Next.js configuration.
func (a *AuthConfig) checkNextJS(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding

	// Check next.config.js or next.config.ts or next.config.mjs
	nextConfigs := []string{"next.config.js", "next.config.ts", "next.config.mjs"}
	var nextConfigPath string
	for _, name := range nextConfigs {
		p := filepath.Join(cfg.Path, name)
		if _, err := os.Stat(p); err == nil {
			nextConfigPath = p
			break
		}
	}

	if nextConfigPath != "" {
		content, err := os.ReadFile(nextConfigPath)
		if err == nil {
			text := string(content)

			// Check for missing security headers
			if !strings.Contains(text, "headers") {
				findings = append(findings, engine.Finding{
					Module:      "auth-config",
					Severity:    engine.SevMedium,
					Title:       "Next.js: no custom security headers configured",
					Description: "next.config does not define custom headers. Security headers like CSP, X-Frame-Options may be missing.",
					Remediation: "Add a headers() function in next.config to set security headers.",
					CWE:         "CWE-693",
					CVSS:        5.0,
				})
			}

			// Check for poweredByHeader not disabled
			if !strings.Contains(text, "poweredByHeader") {
				findings = append(findings, engine.Finding{
					Module:      "auth-config",
					Severity:    engine.SevLow,
					Title:       "Next.js: X-Powered-By header not disabled",
					Description: "The X-Powered-By header reveals framework information to attackers.",
					Remediation: "Set poweredByHeader: false in next.config.",
					CWE:         "CWE-200",
					CVSS:        2.0,
				})
			}
		}
	}

	return findings
}

// checkExpress checks for Express.js security middleware.
func (a *AuthConfig) checkExpress(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding
	ignore := ReadVxIgnore(cfg.Path)

	// Look for main server files
	serverFiles, _ := WalkFiles(cfg.Path, ignore, []string{".js", ".ts"})

	for _, file := range serverFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(content)

		// Only check files that import express
		if !strings.Contains(text, "express") || !strings.Contains(text, "app.listen") {
			continue
		}

		relPath := relativeToRoot(file, cfg.Path)

		if !strings.Contains(text, "helmet") {
			findings = append(findings, engine.Finding{
				Module:      "auth-config",
				Severity:    engine.SevMedium,
				Title:       "Express: helmet middleware not detected",
				Description: fmt.Sprintf("Express server at %s does not use helmet for security headers.", relPath),
				Remediation: "Install and use helmet: app.use(helmet()).",
				CWE:         "CWE-693",
				CVSS:        5.0,
			})
		}

		if !strings.Contains(text, "rateLimit") && !strings.Contains(text, "rate-limit") && !strings.Contains(text, "rateLimiter") {
			findings = append(findings, engine.Finding{
				Module:      "auth-config",
				Severity:    engine.SevMedium,
				Title:       "Express: no rate limiting detected",
				Description: fmt.Sprintf("Express server at %s does not appear to use rate limiting middleware.", relPath),
				Remediation: "Install express-rate-limit: app.use(rateLimit({ windowMs: 15*60*1000, max: 100 })).",
				CWE:         "CWE-770",
				CVSS:        5.0,
			})
		}

		// Only report once per project
		break
	}

	return findings
}

// checkSymfony checks Symfony security configuration.
func (a *AuthConfig) checkSymfony(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding

	securityYaml := filepath.Join(cfg.Path, "config", "packages", "security.yaml")
	if _, err := os.Stat(securityYaml); err != nil {
		return findings
	}

	content, err := os.ReadFile(securityYaml)
	if err != nil {
		return findings
	}
	text := string(content)

	// Check for plaintext password encoder
	if strings.Contains(text, "plaintext") {
		findings = append(findings, engine.Finding{
			Module:      "auth-config",
			Severity:    engine.SevCritical,
			Title:       "Symfony: plaintext password encoder",
			Description: "Security configuration uses plaintext password storage.",
			Remediation: "Use auto or bcrypt/argon2id password hasher.",
			CWE:         "CWE-256",
			CVSS:        9.0,
		})
	}

	// Check for open access patterns
	if strings.Contains(text, "IS_AUTHENTICATED_ANONYMOUSLY") || strings.Contains(text, "PUBLIC_ACCESS") {
		// This is just informational, not necessarily a vulnerability
		findings = append(findings, engine.Finding{
			Module:      "auth-config",
			Severity:    engine.SevInfo,
			Title:       "Symfony: public access routes detected",
			Description: "Some routes are configured with anonymous/public access. Verify this is intentional.",
			Remediation: "Review access_control rules in security.yaml.",
			CWE:         "CWE-284",
		})
	}

	return findings
}

// checkLaravel checks Laravel-specific configuration.
func (a *AuthConfig) checkLaravel(cfg *AuditConfig) []engine.Finding {
	var findings []engine.Finding

	// Check .env for APP_DEBUG=true
	envPath := filepath.Join(cfg.Path, ".env")
	if _, err := os.Stat(envPath); err == nil {
		content, err := os.ReadFile(envPath)
		if err == nil {
			text := string(content)
			if strings.Contains(text, "APP_DEBUG=true") {
				findings = append(findings, engine.Finding{
					Module:      "auth-config",
					Severity:    engine.SevHigh,
					Title:       "Laravel: APP_DEBUG=true",
					Description: "Debug mode is enabled, exposing detailed error pages with stack traces and environment variables.",
					Remediation: "Set APP_DEBUG=false in production .env.",
					CWE:         "CWE-489",
					CVSS:        7.0,
				})
			}
		}
	}

	// Check config/cors.php
	corsConfig := filepath.Join(cfg.Path, "config", "cors.php")
	if _, err := os.Stat(corsConfig); err == nil {
		content, err := os.ReadFile(corsConfig)
		if err == nil {
			text := string(content)
			if strings.Contains(text, "'*'") && strings.Contains(text, "allowed_origins") {
				findings = append(findings, engine.Finding{
					Module:      "auth-config",
					Severity:    engine.SevHigh,
					Title:       "Laravel: CORS wildcard origin",
					Description: "config/cors.php allows all origins (*) which enables cross-origin attacks.",
					Remediation: "Restrict allowed_origins to specific trusted domains.",
					CWE:         "CWE-942",
					CVSS:        7.0,
				})
			}
		}
	}

	return findings
}

// findConfigFiles returns common configuration file paths in the project.
func findConfigFiles(root string) []string {
	candidates := []string{
		".env", ".env.production", ".env.staging",
		"config.yaml", "config.yml", "config.json", "config.toml",
		"app.yaml", "app.yml",
		".eslintrc.json", "tsconfig.json",
	}

	// Also look in config/ directory
	configDir := filepath.Join(root, "config")
	if info, err := os.Stat(configDir); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(configDir)
		for _, entry := range entries {
			if !entry.IsDir() {
				candidates = append(candidates, filepath.Join("config", entry.Name()))
			}
		}
	}

	var files []string
	for _, c := range candidates {
		fullPath := filepath.Join(root, c)
		if _, err := os.Stat(fullPath); err == nil {
			files = append(files, fullPath)
		}
	}
	return files
}

// scanFileForPattern scans a file for a regex pattern and returns findings.
func scanFileForPattern(path string, pattern *regexp.Regexp, root string, template engine.Finding) []engine.Finding {
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

		if pattern.MatchString(line) {
			relPath := relativeToRoot(path, root)
			finding := template
			finding.Description = fmt.Sprintf("%s (file: %s, line: %d)", template.Description, relPath, lineNum)
			finding.Evidence = truncateLine(line, 120)
			findings = append(findings, finding)
		}
	}

	return findings
}
