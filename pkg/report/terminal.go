package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
	bold        = "\033[1m"
	dim         = "\033[2m"
)

func severityColor(s engine.Severity) string {
	switch s {
	case engine.SevCritical:
		return colorRed + bold
	case engine.SevHigh:
		return colorRed
	case engine.SevMedium:
		return colorYellow
	case engine.SevLow:
		return colorBlue
	case engine.SevInfo:
		return colorGray
	}
	return colorWhite
}

func gradeColor(g engine.Grade) string {
	switch g {
	case engine.GradeA:
		return colorGreen + bold
	case engine.GradeB:
		return colorGreen
	case engine.GradeC:
		return colorYellow
	case engine.GradeD:
		return colorRed
	case engine.GradeF:
		return colorRed + bold
	}
	return colorWhite
}

func PrintReport(result engine.ScoreResult) {
	// Sort findings by severity (critical first)
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Severity > result.Findings[j].Severity
	})

	fmt.Println()
	fmt.Printf("  %s══════════════════════════════════════════════%s\n", colorCyan, colorReset)
	fmt.Printf("  %s  VX SECURITY REPORT%s\n", bold, colorReset)
	fmt.Printf("  %s══════════════════════════════════════════════%s\n", colorCyan, colorReset)

	// Score
	gc := gradeColor(result.Grade)
	fmt.Printf("\n  %sScore: %d/100  Grade: %s%s\n\n", gc, result.Score, result.Grade, colorReset)

	// Summary bar
	fmt.Printf("  %sCRITICAL%s: %d  ", colorRed+bold, colorReset, result.Summary[engine.SevCritical])
	fmt.Printf("%sHIGH%s: %d  ", colorRed, colorReset, result.Summary[engine.SevHigh])
	fmt.Printf("%sMEDIUM%s: %d  ", colorYellow, colorReset, result.Summary[engine.SevMedium])
	fmt.Printf("%sLOW%s: %d  ", colorBlue, colorReset, result.Summary[engine.SevLow])
	fmt.Printf("%sINFO%s: %d\n", colorGray, colorReset, result.Summary[engine.SevInfo])

	fmt.Printf("\n  %s──────────────────────────────────────────────%s\n", colorGray, colorReset)

	// Findings
	if len(result.Findings) == 0 {
		fmt.Printf("\n  %sNo findings — target appears secure%s\n", colorGreen, colorReset)
	}

	prevModule := ""
	for _, f := range result.Findings {
		if f.Module != prevModule {
			fmt.Printf("\n  %s[%s]%s\n", colorCyan+bold, strings.ToUpper(f.Module), colorReset)
			prevModule = f.Module
		}

		sc := severityColor(f.Severity)
		fmt.Printf("  %s%-8s%s %s\n", sc, f.Severity, colorReset, f.Title)

		if f.Description != "" {
			fmt.Printf("           %s%s%s\n", dim, f.Description, colorReset)
		}
		if f.Evidence != "" {
			fmt.Printf("           %sEvidence:%s %s\n", colorPurple, colorReset, f.Evidence)
		}
		if f.CWE != "" {
			fmt.Printf("           %sCWE:%s %s", colorGray, colorReset, f.CWE)
			if f.CVSS > 0 {
				fmt.Printf("  %sCVSS:%s %.1f", colorGray, colorReset, f.CVSS)
			}
			fmt.Println()
		}
		if f.Remediation != "" {
			fmt.Printf("           %sFix:%s %s\n", colorGreen, colorReset, f.Remediation)
		}
	}

	fmt.Printf("\n  %s══════════════════════════════════════════════%s\n\n", colorCyan, colorReset)
}

func PrintJSON(result engine.ScoreResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}
