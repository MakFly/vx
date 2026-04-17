package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MakFly/vx/pkg/engine"
	"github.com/MakFly/vx/pkg/local"
	"github.com/MakFly/vx/pkg/report"
	"github.com/spf13/cobra"
)

var (
	auditMinScore int
	auditJSON     bool
	auditVerbose  bool
	auditCI       bool
	auditSARIF    string
	auditBadge    string
	auditMarkdown string
	auditLang     string
)

var auditCmd = &cobra.Command{
	Use:   "audit <path>",
	Short: "Run local security audit on source code",
	Long:  "Performs white-box security auditing on local source code: secrets, dependencies, code patterns, and configuration.",
	Args:  cobra.ExactArgs(1),
	Run:   runAudit,
}

func init() {
	auditCmd.Flags().IntVar(&auditMinScore, "min-score", 0, "Minimum passing score for CI mode (0 = no threshold)")
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "Output results as JSON")
	auditCmd.Flags().BoolVarP(&auditVerbose, "verbose", "v", false, "Verbose output")
	auditCmd.Flags().BoolVar(&auditCI, "ci", false, "CI mode: exit code 1 if score < min-score")
	auditCmd.Flags().StringVar(&auditSARIF, "sarif", "", "Write SARIF report to file")
	auditCmd.Flags().StringVar(&auditBadge, "badge", "", "Write shields.io badge JSON to file")
	auditCmd.Flags().StringVar(&auditMarkdown, "markdown", "", "Write markdown report to file")
	auditCmd.Flags().StringVar(&auditLang, "lang", "", "Override language detection (comma-separated: php,go,typescript)")

	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) {
	path := args[0]

	// Validate path exists
	info, err := os.Stat(path)
	if err != nil {
		exitError(fmt.Sprintf("path not found: %s", path))
	}
	if !info.IsDir() {
		exitError(fmt.Sprintf("path is not a directory: %s", path))
	}

	// Resolve absolute path
	absPath, err := resolveAbsPath(path)
	if err != nil {
		exitError(fmt.Sprintf("cannot resolve path: %v", err))
	}

	// Build audit config
	cfg := &local.AuditConfig{
		Path:    absPath,
		Verbose: auditVerbose,
	}

	// Detect or override languages
	if auditLang != "" {
		cfg.Languages = strings.Split(auditLang, ",")
		for i, l := range cfg.Languages {
			cfg.Languages[i] = strings.TrimSpace(l)
		}
	} else {
		cfg.Languages = local.DetectLanguages(absPath)
	}

	// Run audit
	result := executeAudit(cfg)

	// Output
	if auditJSON {
		report.PrintJSON(result)
	} else {
		report.PrintReport(result)
	}

	writeAuditReports(result, absPath)

	// CI mode exit code
	if auditCI && auditMinScore > 0 && result.Score < auditMinScore {
		fmt.Fprintf(os.Stderr, "FAIL: Score %d < minimum %d\n", result.Score, auditMinScore)
		os.Exit(1)
	}
}

// executeAudit runs all local audit modules and returns a score result.
func executeAudit(cfg *local.AuditConfig) engine.ScoreResult {
	start := time.Now()

	if !auditJSON {
		fmt.Print(banner)
		fmt.Printf("  Local Security Audit v0.1.0\n")
		fmt.Printf("  Path: %s\n", cfg.Path)
		fmt.Printf("  Languages: %s\n\n", strings.Join(cfg.Languages, ", "))
	}

	modules := []local.LocalModule{
		&local.Secrets{},
		&local.EnvFiles{},
		&local.Deps{},
		&local.CodeVulns{},
		&local.AuthConfig{},
	}

	var (
		allFindings []engine.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
	)

	for _, mod := range modules {
		wg.Add(1)
		go func(m local.LocalModule) {
			defer wg.Done()

			if !auditJSON {
				fmt.Printf("  [~] Running %s...\n", m.Name())
			}
			modStart := time.Now()

			findings, err := m.Run(cfg)
			elapsed := time.Since(modStart)

			if err != nil {
				if !auditJSON {
					fmt.Printf("  [!] %s failed: %v (%s)\n", m.Name(), err, elapsed.Round(time.Millisecond))
				}
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()

			if !auditJSON {
				fmt.Printf("  [OK] %s done - %d findings (%s)\n", m.Name(), len(findings), elapsed.Round(time.Millisecond))
			}
		}(mod)
	}

	wg.Wait()

	elapsed := time.Since(start)
	if !auditJSON {
		fmt.Printf("\n  Audit completed in %s\n\n", elapsed.Round(time.Millisecond))
	}

	return engine.ComputeScore(allFindings)
}

func writeAuditReports(result engine.ScoreResult, path string) {
	if auditSARIF != "" {
		if err := report.WriteSARIF(result, auditSARIF); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write SARIF: %v\n", err)
		} else if !auditJSON {
			fmt.Printf("  SARIF report written to %s\n", auditSARIF)
		}
	}

	if auditBadge != "" {
		if err := report.WriteBadge(result, auditBadge); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write badge: %v\n", err)
		} else if !auditJSON {
			fmt.Printf("  Badge JSON written to %s\n", auditBadge)
		}
	}

	if auditMarkdown != "" {
		md := report.GenerateMarkdown(result, path, nil)
		if err := os.WriteFile(auditMarkdown, []byte(md), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write markdown: %v\n", err)
		} else if !auditJSON {
			fmt.Printf("  Markdown report written to %s\n", auditMarkdown)
		}
	}

	// Set GitHub Actions outputs if in CI
	if ghOutput := os.Getenv("GITHUB_OUTPUT"); ghOutput != "" {
		if f, err := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			defer f.Close()
			fmt.Fprintf(f, "score=%d\n", result.Score)
			fmt.Fprintf(f, "grade=%s\n", result.Grade)
			fmt.Fprintf(f, "total-findings=%d\n", len(result.Findings))
			fmt.Fprintf(f, "critical-findings=%d\n", result.Summary[engine.SevCritical])
			fmt.Fprintf(f, "high-findings=%d\n", result.Summary[engine.SevHigh])
		}
	}
}

func resolveAbsPath(path string) (string, error) {
	return filepath.Abs(path)
}
