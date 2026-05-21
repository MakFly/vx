package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
	"github.com/MakFly/vx/pkg/modules"
)

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

func normalizeTarget(raw string) string {
	target := strings.TrimSpace(raw)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	return strings.TrimRight(target, "/")
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func registerRemoteModules(eng *engine.Engine, includeAggressive bool) {
	eng.Register(&modules.Headers{})
	eng.Register(&modules.Cookies{})
	eng.Register(&modules.Discovery{})
	eng.Register(&modules.Webservice{})
	eng.Register(&modules.XSS{})
	eng.Register(&modules.InfoDisclosure{})
	eng.Register(&modules.TLS{})
	eng.Register(&modules.CORS{})
	eng.Register(&modules.HTTPMethods{})
	eng.Register(&modules.SQLi{})
	eng.Register(&modules.JSDiscovery{})
	eng.Register(&modules.OpenRedirect{})
	eng.Register(&modules.PathTraversal{})

	if includeAggressive {
		eng.Register(&modules.PortScan{})
		eng.Register(&modules.Subdomain{})
		eng.Register(&modules.Login{})
	}
}

func writeGithubOutputs(result engine.ScoreResult) {
	ghOutput := os.Getenv("GITHUB_OUTPUT")
	if ghOutput == "" {
		return
	}
	f, err := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "score=%d\n", result.Score)
	fmt.Fprintf(f, "grade=%s\n", result.Grade)
	fmt.Fprintf(f, "total-findings=%d\n", len(result.Findings))
	fmt.Fprintf(f, "critical-findings=%d\n", result.Summary[engine.SevCritical])
	fmt.Fprintf(f, "high-findings=%d\n", result.Summary[engine.SevHigh])
	fmt.Fprintf(f, "partial=%t\n", result.Partial)
}

func failCIIfNeeded(enabled bool, minScore int, result engine.ScoreResult) {
	if !enabled {
		return
	}
	if result.Partial {
		fmt.Fprintf(os.Stderr, "FAIL: scan incomplete (%d module error(s))\n", len(result.Errors))
		os.Exit(1)
	}
	if minScore > 0 && result.Score < minScore {
		fmt.Fprintf(os.Stderr, "FAIL: Score %d < minimum %d\n", result.Score, minScore)
		os.Exit(1)
	}
}
