package modules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

type Subdomain struct{}

func (s *Subdomain) Name() string        { return "subdomain" }
func (s *Subdomain) Description() string { return "Subdomain enumeration via DNS and HTTP probing" }

var commonSubdomains = []string{
	"www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta", "app",
	"cms", "blog", "shop", "store", "portal", "vpn", "remote", "git", "gitlab", "jenkins",
	"ci", "cd", "monitoring", "grafana", "kibana", "elastic", "redis", "db", "database", "mysql",
	"postgres", "mongo", "backup", "old", "new", "v2", "m", "mobile", "static", "cdn",
	"assets", "media", "img", "images", "files", "upload", "download", "docs", "wiki", "help",
	"support", "status", "dashboard", "panel", "login", "auth", "sso", "oauth", "id", "accounts",
	"billing", "pay", "checkout", "cart", "search", "api-v1", "api-v2", "internal", "intranet",
	"extranet", "staging2", "preprod", "uat", "qa", "sandbox", "demo", "edge", "origin", "lb",
	"proxy", "cache", "queue", "mq", "ws", "socket", "realtime", "notify", "push", "cron",
	"worker", "task", "job", "webhook",
}

var sensitiveSubdomains = map[string]bool{
	"admin": true, "staging": true, "staging2": true, "internal": true, "intranet": true,
	"preprod": true, "uat": true, "qa": true, "sandbox": true, "test": true, "dev": true,
	"jenkins": true, "gitlab": true, "git": true, "ci": true, "cd": true,
	"grafana": true, "kibana": true, "elastic": true, "monitoring": true,
	"panel": true, "dashboard": true, "backup": true, "db": true, "database": true,
	"redis": true, "mysql": true, "postgres": true, "mongo": true,
}

type subdomainResult struct {
	subdomain string
	ips       []string
	httpOK    bool
	httpsOK   bool
}

func (s *Subdomain) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	host := extractHost(cfg.TargetURL)
	if host == "" {
		return nil, fmt.Errorf("could not extract host from %s", cfg.TargetURL)
	}

	// Strip www. to get the base domain
	domain := strings.TrimPrefix(host, "www.")

	// Skip if it looks like an IP address
	if net.ParseIP(domain) != nil {
		return nil, nil
	}

	var (
		results []subdomainResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, 20)

	for _, sub := range commonSubdomains {
		wg.Add(1)
		sem <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := sub + "." + domain

			ips, err := net.LookupHost(fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			result := subdomainResult{
				subdomain: sub,
				ips:       ips,
			}

			// HTTP probe
			httpClient := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			if resp, err := httpClient.Get("http://" + fqdn); err == nil {
				resp.Body.Close()
				result.httpOK = true
			}
			if resp, err := httpClient.Get("https://" + fqdn); err == nil {
				resp.Body.Close()
				result.httpsOK = true
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()

	var findings []engine.Finding

	if len(results) == 0 {
		return findings, nil
	}

	// Summary finding
	var subNames []string
	for _, r := range results {
		label := r.subdomain
		if r.httpsOK {
			label += " (HTTPS)"
		} else if r.httpOK {
			label += " (HTTP)"
		} else {
			label += " (DNS only)"
		}
		subNames = append(subNames, label)
	}

	findings = append(findings, engine.Finding{
		Module:      s.Name(),
		Severity:    engine.SevInfo,
		Title:       fmt.Sprintf("%d subdomain(s) discovered for %s", len(results), domain),
		Description: "DNS enumeration found active subdomains",
		Evidence:    strings.Join(subNames, ", "),
	})

	// Flag sensitive subdomains
	for _, r := range results {
		if !sensitiveSubdomains[r.subdomain] {
			continue
		}
		if !r.httpOK && !r.httpsOK {
			continue // DNS only, no web service — lower risk
		}

		fqdn := r.subdomain + "." + domain
		proto := "HTTP"
		if r.httpsOK {
			proto = "HTTPS"
		}

		findings = append(findings, engine.Finding{
			Module:      s.Name(),
			Severity:    engine.SevMedium,
			Title:       fmt.Sprintf("Sensitive subdomain accessible: %s", fqdn),
			Description: fmt.Sprintf("The subdomain '%s' suggests an internal/administrative service and is reachable via %s", r.subdomain, proto),
			Evidence:    fmt.Sprintf("%s → %s (%s reachable)", fqdn, strings.Join(r.ips, ", "), proto),
			CWE:         "CWE-200",
			Remediation: fmt.Sprintf("Restrict access to %s via firewall rules, VPN, or IP allowlist. Remove DNS record if the service is not needed.", fqdn),
		})
	}

	return findings, nil
}
