package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

type htmlData struct {
	Target       string
	Date         string
	Score        int
	Grade        engine.Grade
	GradeColor   string
	ScoreColor   string
	Findings     []engine.Finding
	Modules      []htmlModule
	Summary      map[string]int
	CriticalCount int
	HighCount    int
	MediumCount  int
	LowCount     int
	InfoCount    int
	TotalCount   int
}

type htmlModule struct {
	Name     string
	Findings []engine.Finding
}

func severityHTMLColor(s engine.Severity) string {
	switch s {
	case engine.SevCritical:
		return "#ff4757"
	case engine.SevHigh:
		return "#ff6b35"
	case engine.SevMedium:
		return "#ffa502"
	case engine.SevLow:
		return "#3742fa"
	case engine.SevInfo:
		return "#747d8c"
	}
	return "#747d8c"
}

func gradeHTMLColor(g engine.Grade) string {
	switch g {
	case engine.GradeA:
		return "#2ed573"
	case engine.GradeB:
		return "#7bed9f"
	case engine.GradeC:
		return "#ffa502"
	case engine.GradeD:
		return "#ff6b35"
	case engine.GradeF:
		return "#ff4757"
	}
	return "#747d8c"
}

// WriteHTML generates a standalone HTML report file with embedded CSS.
func WriteHTML(result engine.ScoreResult, target string, path string) error {
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Severity > result.Findings[j].Severity
	})

	// Group findings by module
	modMap := make(map[string][]engine.Finding)
	var modOrder []string
	for _, f := range result.Findings {
		if _, ok := modMap[f.Module]; !ok {
			modOrder = append(modOrder, f.Module)
		}
		modMap[f.Module] = append(modMap[f.Module], f)
	}

	var modules []htmlModule
	for _, name := range modOrder {
		modules = append(modules, htmlModule{Name: name, Findings: modMap[name]})
	}

	data := htmlData{
		Target:        target,
		Date:          time.Now().Format("2006-01-02 15:04:05 MST"),
		Score:         result.Score,
		Grade:         result.Grade,
		GradeColor:    gradeHTMLColor(result.Grade),
		ScoreColor:    gradeHTMLColor(result.Grade),
		Findings:      result.Findings,
		Modules:       modules,
		CriticalCount: result.Summary[engine.SevCritical],
		HighCount:     result.Summary[engine.SevHigh],
		MediumCount:   result.Summary[engine.SevMedium],
		LowCount:      result.Summary[engine.SevLow],
		InfoCount:     result.Summary[engine.SevInfo],
		TotalCount:    len(result.Findings),
	}

	funcMap := template.FuncMap{
		"upper":        strings.ToUpper,
		"sevColor":     severityHTMLColor,
		"hasCWE":       func(s string) bool { return s != "" },
		"hasEvidence":  func(s string) bool { return s != "" },
		"hasRemediation": func(s string) bool { return s != "" },
		"cweURL": func(cwe string) string {
			id := strings.TrimPrefix(cwe, "CWE-")
			return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", id)
		},
		"scoreDashOffset": func(score int) int {
			// Circle circumference is 283; offset = 283 - (283 * score / 100)
			return 283 - (283 * score / 100)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create HTML file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VX Security Report — {{.Target}}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0f0f13;color:#e4e4e7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6}
  .container{max-width:960px;margin:0 auto;padding:24px 16px}
  header{text-align:center;padding:40px 0 32px}
  header h1{font-size:28px;font-weight:700;color:#fff;margin-bottom:4px}
  header .target{color:#a1a1aa;font-size:14px;font-family:monospace;margin-top:8px}
  header .date{color:#71717a;font-size:12px;margin-top:4px}
  .score-section{display:flex;align-items:center;justify-content:center;gap:32px;margin:24px 0 32px}
  .gauge{position:relative;width:120px;height:120px}
  .gauge svg{transform:rotate(-90deg)}
  .gauge-bg{fill:none;stroke:#27272a;stroke-width:8}
  .gauge-fill{fill:none;stroke:{{.ScoreColor}};stroke-width:8;stroke-linecap:round;stroke-dasharray:283;stroke-dashoffset:{{scoreDashOffset .Score}};transition:stroke-dashoffset 1s ease}
  .gauge-text{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
  .gauge-score{font-size:32px;font-weight:800;color:#fff}
  .gauge-label{font-size:11px;color:#71717a;text-transform:uppercase;letter-spacing:1px}
  .grade-badge{font-size:64px;font-weight:900;color:{{.GradeColor}}}
  .summary-bar{display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-bottom:32px}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;font-size:13px;font-weight:600;background:#1a1a22}
  .pill .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
  .pill.critical .dot{background:#ff4757}
  .pill.high .dot{background:#ff6b35}
  .pill.medium .dot{background:#ffa502}
  .pill.low .dot{background:#3742fa}
  .pill.info .dot{background:#747d8c}
  .module{background:#18181b;border:1px solid #27272a;border-radius:12px;margin-bottom:16px;overflow:hidden}
  .module-header{padding:14px 20px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;user-select:none}
  .module-header:hover{background:#1f1f24}
  .module-header h2{font-size:15px;font-weight:600;color:#e4e4e7;text-transform:uppercase;letter-spacing:.5px}
  .module-header .count{color:#71717a;font-size:13px}
  .module-header .chevron{color:#71717a;transition:transform .2s}
  .module.collapsed .module-body{display:none}
  .module.collapsed .chevron{transform:rotate(-90deg)}
  .finding{padding:16px 20px;border-top:1px solid #27272a}
  .finding-header{display:flex;align-items:center;gap:10px;margin-bottom:8px}
  .sev-badge{padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff}
  .finding-title{font-size:14px;font-weight:600;color:#fff}
  .finding-desc{font-size:13px;color:#a1a1aa;margin-bottom:8px}
  .evidence{background:#0c0c10;border:1px solid #27272a;border-radius:6px;padding:10px 14px;font-family:'Fira Code',monospace;font-size:12px;color:#d4d4d8;margin-bottom:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
  .meta{display:flex;gap:16px;flex-wrap:wrap;font-size:12px}
  .meta a{color:#60a5fa;text-decoration:none}
  .meta a:hover{text-decoration:underline}
  .meta .fix{color:#34d399}
  footer{text-align:center;padding:32px 0;color:#52525b;font-size:12px;border-top:1px solid #27272a;margin-top:24px}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>VX Security Report</h1>
    <div class="target">{{.Target}}</div>
    <div class="date">{{.Date}}</div>
  </header>

  <div class="score-section">
    <div class="gauge">
      <svg viewBox="0 0 100 100">
        <circle class="gauge-bg" cx="50" cy="50" r="45"/>
        <circle class="gauge-fill" cx="50" cy="50" r="45"/>
      </svg>
      <div class="gauge-text">
        <div class="gauge-score">{{.Score}}</div>
        <div class="gauge-label">/ 100</div>
      </div>
    </div>
    <div class="grade-badge">{{.Grade}}</div>
  </div>

  <div class="summary-bar">
    <span class="pill critical"><span class="dot"></span> Critical: {{.CriticalCount}}</span>
    <span class="pill high"><span class="dot"></span> High: {{.HighCount}}</span>
    <span class="pill medium"><span class="dot"></span> Medium: {{.MediumCount}}</span>
    <span class="pill low"><span class="dot"></span> Low: {{.LowCount}}</span>
    <span class="pill info"><span class="dot"></span> Info: {{.InfoCount}}</span>
  </div>

  {{range .Modules}}
  <div class="module" onclick="this.classList.toggle('collapsed')">
    <div class="module-header">
      <h2>{{upper .Name}}</h2>
      <div>
        <span class="count">{{len .Findings}} finding{{if gt (len .Findings) 1}}s{{end}}</span>
        <span class="chevron">&#9660;</span>
      </div>
    </div>
    <div class="module-body">
      {{range .Findings}}
      <div class="finding">
        <div class="finding-header">
          <span class="sev-badge" style="background:{{sevColor .Severity}}">{{.Severity}}</span>
          <span class="finding-title">{{.Title}}</span>
        </div>
        {{if .Description}}<div class="finding-desc">{{.Description}}</div>{{end}}
        {{if hasEvidence .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
        <div class="meta">
          {{if hasCWE .CWE}}<a href="{{cweURL .CWE}}" target="_blank" rel="noopener">{{.CWE}}</a>{{end}}
          {{if gt .CVSS 0.0}}<span>CVSS: {{printf "%.1f" .CVSS}}</span>{{end}}
          {{if hasRemediation .Remediation}}<span class="fix">Fix: {{.Remediation}}</span>{{end}}
        </div>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}

  {{if eq .TotalCount 0}}
  <div style="text-align:center;padding:48px 0;color:#34d399;font-size:18px;font-weight:600">
    No findings — target appears secure
  </div>
  {{end}}

  <footer>Generated by VX Security Scanner v0.1.0</footer>
</div>
</body>
</html>`
