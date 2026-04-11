package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
	"github.com/MakFly/vx/pkg/local"
	"github.com/MakFly/vx/pkg/modules"
	"github.com/MakFly/vx/pkg/report"
	"github.com/spf13/cobra"
)

var (
	fullURL      string
	fullMinScore int
	fullJSON     bool
	fullVerbose  bool
	fullCI       bool
	fullSARIF    string
	fullBadge    string
	fullMarkdown string
	fullLang     string
	fullThreads  int
	fullTimeout  int
)

var fullCmd = &cobra.Command{
	Use:   "full <path> --url <url>",
	Short: "Run both remote scan and local audit",
	Long:  "Performs combined black-box remote scanning and white-box local auditing, producing a unified report.",
	Args:  cobra.ExactArgs(1),
	Run:   runFull,
}

func init() {
	fullCmd.Flags().StringVar(&fullURL, "url", "", "Target URL for remote scan (required)")
	fullCmd.Flags().IntVar(&fullMinScore, "min-score", 0, "Minimum passing score for CI mode")
	fullCmd.Flags().BoolVar(&fullJSON, "json", false, "Output results as JSON")
	fullCmd.Flags().BoolVarP(&fullVerbose, "verbose", "v", false, "Verbose output")
	fullCmd.Flags().BoolVar(&fullCI, "ci", false, "CI mode: exit code 1 if score < min-score")
	fullCmd.Flags().StringVar(&fullSARIF, "sarif", "", "Write SARIF report to file")
	fullCmd.Flags().StringVar(&fullBadge, "badge", "", "Write shields.io badge JSON to file")
	fullCmd.Flags().StringVar(&fullMarkdown, "markdown", "", "Write markdown report to file")
	fullCmd.Flags().StringVar(&fullLang, "lang", "", "Override language detection (comma-separated)")
	fullCmd.Flags().IntVarP(&fullThreads, "threads", "t", 10, "Number of concurrent scan threads")
	fullCmd.Flags().IntVar(&fullTimeout, "timeout", 15, "HTTP request timeout in seconds")

	_ = fullCmd.MarkFlagRequired("url")

	rootCmd.AddCommand(fullCmd)
}

func runFull(cmd *cobra.Command, args []string) {
	path := args[0]
	target := fullURL

	// Validate path
	info, err := os.Stat(path)
	if err != nil {
		exitError(fmt.Sprintf("path not found: %s", path))
	}
	if !info.IsDir() {
		exitError(fmt.Sprintf("path is not a directory: %s", path))
	}

	absPath, err := resolveAbsPath(path)
	if err != nil {
		exitError(fmt.Sprintf("cannot resolve path: %v", err))
	}

	// Normalize URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimRight(target, "/")

	if !fullJSON {
		fmt.Print(banner)
		fmt.Printf("  Full Security Analysis v0.1.0\n")
		fmt.Printf("  Remote Target: %s\n", target)
		fmt.Printf("  Local Path: %s\n\n", absPath)
	}

	start := time.Now()

	// --- Phase 1: Remote scan ---
	if !fullJSON {
		fmt.Printf("  === Phase 1: Remote Scan ===\n\n")
	}

	scanCfg := &engine.Config{
		TargetURL: target,
		Threads:   fullThreads,
		Timeout:   time.Duration(fullTimeout) * time.Second,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Verbose:   fullVerbose,
	}

	eng := engine.New(scanCfg)
	eng.Register(&modules.Headers{})
	eng.Register(&modules.Cookies{})
	eng.Register(&modules.Discovery{})
	eng.Register(&modules.Webservice{})
	eng.Register(&modules.XSS{})
	eng.Register(&modules.InfoDisclosure{})

	remoteResult := eng.Run()

	// --- Phase 2: Local audit ---
	if !fullJSON {
		fmt.Printf("\n  === Phase 2: Local Audit ===\n\n")
	}

	auditCfg := &local.AuditConfig{
		Path:    absPath,
		Verbose: fullVerbose,
	}

	if fullLang != "" {
		auditCfg.Languages = strings.Split(fullLang, ",")
		for i, l := range auditCfg.Languages {
			auditCfg.Languages[i] = strings.TrimSpace(l)
		}
	} else {
		auditCfg.Languages = local.DetectLanguages(absPath)
	}

	// Temporarily override package-level audit flags for executeAudit
	savedJSON := auditJSON
	auditJSON = fullJSON
	localResult := executeAudit(auditCfg)
	auditJSON = savedJSON

	// --- Combine results ---
	allFindings := append(remoteResult.Findings, localResult.Findings...)
	combined := engine.ComputeScore(allFindings)

	elapsed := time.Since(start)

	if !fullJSON {
		fmt.Printf("\n  Full analysis completed in %s\n\n", elapsed.Round(time.Millisecond))
	}

	// Output
	if fullJSON {
		report.PrintJSON(combined)
	} else {
		report.PrintReport(combined)
	}

	// Write reports
	if fullSARIF != "" {
		if err := report.WriteSARIF(combined, fullSARIF); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write SARIF: %v\n", err)
		} else if !fullJSON {
			fmt.Printf("  SARIF report written to %s\n", fullSARIF)
		}
	}

	if fullBadge != "" {
		if err := report.WriteBadge(combined, fullBadge); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write badge: %v\n", err)
		} else if !fullJSON {
			fmt.Printf("  Badge JSON written to %s\n", fullBadge)
		}
	}

	if fullMarkdown != "" {
		md := report.GenerateMarkdown(combined, target, nil)
		if err := os.WriteFile(fullMarkdown, []byte(md), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write markdown: %v\n", err)
		} else if !fullJSON {
			fmt.Printf("  Markdown report written to %s\n", fullMarkdown)
		}
	}

	// GitHub Actions outputs
	if ghOutput := os.Getenv("GITHUB_OUTPUT"); ghOutput != "" {
		f, err := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintf(f, "score=%d\n", combined.Score)
			fmt.Fprintf(f, "grade=%s\n", combined.Grade)
			fmt.Fprintf(f, "total-findings=%d\n", len(combined.Findings))
			fmt.Fprintf(f, "critical-findings=%d\n", combined.Summary[engine.SevCritical])
			fmt.Fprintf(f, "high-findings=%d\n", combined.Summary[engine.SevHigh])
			f.Close()
		}
	}

	// CI mode exit code
	if fullCI && fullMinScore > 0 && combined.Score < fullMinScore {
		fmt.Fprintf(os.Stderr, "FAIL: Score %d < minimum %d\n", combined.Score, fullMinScore)
		os.Exit(1)
	}
}
