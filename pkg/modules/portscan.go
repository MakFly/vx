package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

type PortScan struct{}

func (p *PortScan) Name() string        { return "portscan" }
func (p *PortScan) Description() string { return "TCP port scanner for common services" }

type portInfo struct {
	port    int
	service string
	risky   bool
}

var commonPorts = []portInfo{
	{21, "FTP", false},
	{22, "SSH", false},
	{23, "Telnet", true},
	{25, "SMTP", false},
	{53, "DNS", false},
	{80, "HTTP", false},
	{110, "POP3", false},
	{143, "IMAP", false},
	{443, "HTTPS", false},
	{445, "SMB", true},
	{993, "IMAPS", false},
	{995, "POP3S", false},
	{1433, "MSSQL", true},
	{3306, "MySQL", true},
	{3389, "RDP", true},
	{5432, "PostgreSQL", true},
	{6379, "Redis", true},
	{8080, "HTTP-Alt", false},
	{8443, "HTTPS-Alt", false},
	{27017, "MongoDB", true},
}

func (p *PortScan) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	host := extractHost(cfg.TargetURL)
	if host == "" {
		return nil, fmt.Errorf("could not extract host from %s", cfg.TargetURL)
	}

	var (
		findings []engine.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	// Limit concurrency for port scanning
	sem := make(chan struct{}, 10)

	var openPorts []string
	var riskyPorts []string

	for _, pi := range commonPorts {
		wg.Add(1)
		sem <- struct{}{}

		go func(pi portInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", pi.port))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			defer mu.Unlock()

			label := fmt.Sprintf("%d/%s", pi.port, pi.service)
			openPorts = append(openPorts, label)
			if pi.risky {
				riskyPorts = append(riskyPorts, label)
			}
		}(pi)
	}

	wg.Wait()

	// Summary finding for all open ports
	if len(openPorts) > 0 {
		findings = append(findings, engine.Finding{
			Module:      p.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("%d open port(s) detected", len(openPorts)),
			Description: "TCP port scan identified open services on the target host",
			Evidence:    strings.Join(openPorts, ", "),
		})
	}

	// Individual findings for risky ports
	for _, rp := range riskyPorts {
		parts := strings.SplitN(rp, "/", 2)
		service := ""
		if len(parts) == 2 {
			service = parts[1]
		}
		port := parts[0]

		sev := engine.SevHigh
		desc := fmt.Sprintf("Port %s (%s) is open and publicly accessible. This service should not be exposed to the internet.", port, service)
		remediation := fmt.Sprintf("Restrict access to port %s using a firewall. Only allow connections from trusted IPs or use a VPN.", port)
		cwe := "CWE-284"

		switch service {
		case "Telnet":
			desc = fmt.Sprintf("Telnet (port %s) is open — transmits credentials in plaintext", port)
			remediation = "Disable Telnet and use SSH instead"
			cwe = "CWE-319"
		case "SMB":
			desc = fmt.Sprintf("SMB (port %s) is publicly accessible — high-risk for ransomware and lateral movement", port)
			cwe = "CWE-284"
		case "Redis":
			desc = fmt.Sprintf("Redis (port %s) is publicly accessible — often runs without authentication", port)
			cwe = "CWE-306"
		case "MongoDB":
			desc = fmt.Sprintf("MongoDB (port %s) is publicly accessible — commonly misconfigured without auth", port)
			cwe = "CWE-306"
		case "MySQL", "PostgreSQL", "MSSQL":
			desc = fmt.Sprintf("Database service %s (port %s) is publicly accessible", service, port)
			cwe = "CWE-284"
		case "RDP":
			desc = fmt.Sprintf("RDP (port %s) is publicly accessible — high-risk for brute force and exploitation", port)
			cwe = "CWE-284"
		}

		findings = append(findings, engine.Finding{
			Module:      p.Name(),
			Severity:    sev,
			Title:       fmt.Sprintf("Dangerous service exposed: %s (port %s)", service, port),
			Description: desc,
			Evidence:    fmt.Sprintf("TCP connect to %s:%s succeeded", extractHost(cfg.TargetURL), port),
			CWE:         cwe,
			CVSS:        7.5,
			Remediation: remediation,
		})
	}

	return findings, nil
}
