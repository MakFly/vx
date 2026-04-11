package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/MakFly/vx/pkg/history"
	"github.com/MakFly/vx/pkg/report"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Browse and export scan history",
}

var historyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved scans",
	Run:   runHistoryList,
}

var historyShowCmd = &cobra.Command{
	Use:   "show <filename>",
	Short: "Show full report for a saved scan",
	Args:  cobra.ExactArgs(1),
	Run:   runHistoryShow,
}

var historyCompareCmd = &cobra.Command{
	Use:   "compare <file1> <file2>",
	Short: "Compare two scans and show delta",
	Args:  cobra.ExactArgs(2),
	Run:   runHistoryCompare,
}

var historyExportCmd = &cobra.Command{
	Use:   "export <filename>",
	Short: "Export a saved scan as HTML",
	Args:  cobra.ExactArgs(1),
	Run:   runHistoryExport,
}

var historyExportHTML string

func init() {
	historyExportCmd.Flags().StringVar(&historyExportHTML, "html", "", "Output HTML file path")

	historyCmd.AddCommand(historyListCmd)
	historyCmd.AddCommand(historyShowCmd)
	historyCmd.AddCommand(historyCompareCmd)
	historyCmd.AddCommand(historyExportCmd)

	rootCmd.AddCommand(historyCmd)
}

func runHistoryList(cmd *cobra.Command, args []string) {
	scans, err := history.ListScans()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(scans) == 0 {
		fmt.Println("  No scans in history. Run 'vx scan <url>' to start.")
		return
	}

	fmt.Printf("\n  %-24s %-30s %6s %6s %8s %10s\n", "DATE", "TARGET", "SCORE", "GRADE", "FINDINGS", "DURATION")
	fmt.Printf("  %s\n", strings.Repeat("-", 90))

	for _, s := range scans {
		fmt.Printf("  %-24s %-30s %6d %6s %8d %10s\n",
			s.Date.Format("2006-01-02 15:04:05"),
			truncate(s.Target, 30),
			s.Score,
			s.Grade,
			s.Findings,
			s.Duration.Round(1e6),
		)
	}

	fmt.Printf("\n  %d scan(s) found.\n", len(scans))
	fmt.Printf("  Files: ~/.vx/scans/\n\n")
}

func runHistoryShow(cmd *cobra.Command, args []string) {
	result, err := history.LoadScanResult(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	report.PrintReport(*result)
}

func runHistoryCompare(cmd *cobra.Command, args []string) {
	diff, err := history.ComparScans(args[0], args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n  Scan Comparison\n")
	fmt.Printf("  %s\n", strings.Repeat("-", 40))
	fmt.Printf("  Score A: %d/100\n", diff.ScoreA)
	fmt.Printf("  Score B: %d/100\n", diff.ScoreB)

	if diff.Delta > 0 {
		fmt.Printf("  Delta:   +%d (improved)\n", diff.Delta)
	} else if diff.Delta < 0 {
		fmt.Printf("  Delta:   %d (regressed)\n", diff.Delta)
	} else {
		fmt.Printf("  Delta:   0 (no change)\n")
	}

	if len(diff.NewFindings) > 0 {
		fmt.Printf("\n  New Findings (%d):\n", len(diff.NewFindings))
		for _, f := range diff.NewFindings {
			fmt.Printf("    [%s] %s: %s\n", f.Severity, f.Module, f.Title)
		}
	}

	if len(diff.FixedFindings) > 0 {
		fmt.Printf("\n  Fixed Findings (%d):\n", len(diff.FixedFindings))
		for _, f := range diff.FixedFindings {
			fmt.Printf("    [%s] %s: %s\n", f.Severity, f.Module, f.Title)
		}
	}

	fmt.Println()
}

func runHistoryExport(cmd *cobra.Command, args []string) {
	if historyExportHTML == "" {
		fmt.Fprintln(os.Stderr, "Error: --html flag is required")
		os.Exit(1)
	}

	stored, err := history.LoadScan(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := report.WriteHTML(stored.Result, stored.Target, historyExportHTML); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing HTML: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  HTML report written to %s\n", historyExportHTML)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
