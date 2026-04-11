package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/config"
	"github.com/MakFly/vx/pkg/engine"
	"github.com/MakFly/vx/pkg/history"
	"github.com/MakFly/vx/pkg/modules"
	"github.com/MakFly/vx/pkg/report"
	"github.com/spf13/cobra"
)

var (
	scanThreads  int
	scanTimeout  int
	scanModules  string
	scanMinScore int
	scanJSON     bool
	scanVerbose  bool
	scanCI       bool
	scanSARIF    string
	scanBadge    string
	scanMarkdown string
	scanHTML     string
)

var scanCmd = &cobra.Command{
	Use:   "scan <url>",
	Short: "Run remote security scan on a target URL",
	Long:  "Performs black-box security testing against a live web application",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

func init() {
	scanCmd.Flags().IntVarP(&scanThreads, "threads", "t", 10, "Number of concurrent module threads")
	scanCmd.Flags().IntVar(&scanTimeout, "timeout", 15, "HTTP request timeout in seconds")
	scanCmd.Flags().StringVarP(&scanModules, "modules", "m", "", "Comma-separated list of modules to run (default: all)")
	scanCmd.Flags().IntVar(&scanMinScore, "min-score", 0, "Minimum passing score for CI mode (0 = no threshold)")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVarP(&scanVerbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolVar(&scanCI, "ci", false, "CI mode: exit code 1 if score < min-score")
	scanCmd.Flags().StringVar(&scanSARIF, "sarif", "", "Write SARIF report to file (for GitHub Code Scanning)")
	scanCmd.Flags().StringVar(&scanBadge, "badge", "", "Write shields.io badge JSON to file")
	scanCmd.Flags().StringVar(&scanMarkdown, "markdown", "", "Write markdown report to file (for PR comments)")
	scanCmd.Flags().StringVar(&scanHTML, "html", "", "Write HTML report to file")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) {
	target := args[0]

	// Load vx.yaml config as defaults (CLI flags override)
	fileCfg, err := config.LoadConfig("vx.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load vx.yaml: %v\n", err)
	}
	applyConfigDefaults(fileCfg, cmd)

	// Normalize URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimRight(target, "/")

	cfg := &engine.Config{
		TargetURL:  target,
		Threads:    scanThreads,
		Timeout:    time.Duration(scanTimeout) * time.Second,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		MinScore:   scanMinScore,
		OutputJSON: scanJSON,
		Verbose:    scanVerbose,
	}

	if scanModules != "" {
		cfg.Modules = strings.Split(scanModules, ",")
	}

	// Print banner
	if !scanJSON {
		fmt.Print(banner)
	}

	// Build engine
	eng := engine.New(cfg)

	// Register all modules
	eng.Register(&modules.Headers{})
	eng.Register(&modules.Cookies{})
	eng.Register(&modules.Discovery{})
	eng.Register(&modules.Webservice{})
	eng.Register(&modules.XSS{})
	eng.Register(&modules.InfoDisclosure{})
	eng.Register(&modules.TLS{})
	eng.Register(&modules.CORS{})
	eng.Register(&modules.PortScan{})
	eng.Register(&modules.Subdomain{})
	eng.Register(&modules.Login{})
	eng.Register(&modules.HTTPMethods{})
	eng.Register(&modules.SQLi{})
	eng.Register(&modules.JSDiscovery{})
	eng.Register(&modules.OpenRedirect{})
	eng.Register(&modules.PathTraversal{})

	// Run
	scanStart := time.Now()
	result := eng.Run()
	scanDuration := time.Since(scanStart)

	// Output
	if scanJSON {
		report.PrintJSON(result)
	} else {
		report.PrintReport(result)
	}

	// Write optional report files
	if scanSARIF != "" {
		if err := report.WriteSARIF(result, scanSARIF); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write SARIF: %v\n", err)
		} else {
			fmt.Printf("  SARIF report written to %s\n", scanSARIF)
		}
	}

	if scanBadge != "" {
		if err := report.WriteBadge(result, scanBadge); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write badge: %v\n", err)
		} else {
			fmt.Printf("  Badge JSON written to %s\n", scanBadge)
		}
	}

	if scanMarkdown != "" {
		md := report.GenerateMarkdown(result, target, nil)
		if err := os.WriteFile(scanMarkdown, []byte(md), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write markdown: %v\n", err)
		} else {
			fmt.Printf("  Markdown report written to %s\n", scanMarkdown)
		}
	}

	// Write HTML report
	if scanHTML != "" {
		if err := report.WriteHTML(result, target, scanHTML); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write HTML: %v\n", err)
		} else {
			fmt.Printf("  HTML report written to %s\n", scanHTML)
		}
	}

	// Save to history
	if err := history.SaveScan(result, target, scanDuration); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save scan history: %v\n", err)
	}

	// Set GitHub Actions outputs if in CI
	if ghOutput := os.Getenv("GITHUB_OUTPUT"); ghOutput != "" {
		f, err := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintf(f, "score=%d\n", result.Score)
			fmt.Fprintf(f, "grade=%s\n", result.Grade)
			fmt.Fprintf(f, "total-findings=%d\n", len(result.Findings))
			fmt.Fprintf(f, "critical-findings=%d\n", result.Summary[engine.SevCritical])
			fmt.Fprintf(f, "high-findings=%d\n", result.Summary[engine.SevHigh])
			f.Close()
		}
	}

	// CI mode exit code
	if scanCI && scanMinScore > 0 && result.Score < scanMinScore {
		fmt.Fprintf(os.Stderr, "FAIL: Score %d < minimum %d\n", result.Score, scanMinScore)
		os.Exit(1)
	}
}

// applyConfigDefaults applies vx.yaml values as defaults for flags not explicitly set.
func applyConfigDefaults(fileCfg *config.Config, cmd *cobra.Command) {
	if fileCfg == nil {
		return
	}

	// Only apply config values for flags not explicitly set on the CLI
	if !cmd.Flags().Changed("threads") && fileCfg.Threads > 0 {
		scanThreads = fileCfg.Threads
	}
	if !cmd.Flags().Changed("timeout") && fileCfg.Timeout > 0 {
		scanTimeout = fileCfg.Timeout
	}
	if !cmd.Flags().Changed("modules") && len(fileCfg.Modules) > 0 {
		scanModules = strings.Join(fileCfg.Modules, ",")
	}
	if !cmd.Flags().Changed("min-score") && fileCfg.CI.MinScore > 0 {
		scanMinScore = fileCfg.CI.MinScore
	}
	if !cmd.Flags().Changed("ci") && fileCfg.CI.FailOnScore {
		scanCI = true
	}
	if !cmd.Flags().Changed("sarif") && fileCfg.Output.SARIF != "" {
		scanSARIF = fileCfg.Output.SARIF
	}
	if !cmd.Flags().Changed("badge") && fileCfg.Output.Badge != "" {
		scanBadge = fileCfg.Output.Badge
	}
	if !cmd.Flags().Changed("markdown") && fileCfg.Output.Markdown != "" {
		scanMarkdown = fileCfg.Output.Markdown
	}
	if !cmd.Flags().Changed("html") && fileCfg.Output.HTML != "" {
		scanHTML = fileCfg.Output.HTML
	}
}
