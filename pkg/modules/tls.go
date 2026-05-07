package modules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

type TLS struct{}

func (t *TLS) Name() string        { return "tls" }
func (t *TLS) Description() string { return "TLS/SSL certificate and configuration analysis" }

func (t *TLS) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	host := extractHost(cfg.TargetURL)
	if host == "" {
		return nil, fmt.Errorf("could not extract host from %s", cfg.TargetURL)
	}

	// Only check HTTPS targets
	if !strings.HasPrefix(cfg.TargetURL, "https://") {
		return []engine.Finding{{
			Module:      t.Name(),
			Severity:    engine.SevHigh,
			Title:       "Site not using HTTPS",
			Description: "The target URL uses HTTP instead of HTTPS, all traffic is unencrypted",
			CWE:         "CWE-319",
			Remediation: "Enable HTTPS with a valid TLS certificate",
		}}, nil
	}

	var findings []engine.Finding

	// Connect with TLS and inspect the connection state
	addr := net.JoinHostPort(host, "443")
	dialer := &net.Dialer{Timeout: cfg.Timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check TLS version
	findings = append(findings, t.checkVersion(state)...)

	// Check certificates
	if len(state.PeerCertificates) > 0 {
		findings = append(findings, t.checkCertificate(state.PeerCertificates[0], host)...)
		findings = append(findings, t.checkChain(state)...)
	}

	// Check cipher suite
	findings = append(findings, t.checkCipher(state)...)

	// Test for deprecated TLS versions
	findings = append(findings, t.probeDeprecatedVersions(host, cfg.Timeout)...)

	return findings, nil
}

func (t *TLS) checkVersion(state tls.ConnectionState) []engine.Finding {
	var findings []engine.Finding

	version := state.Version
	versionName := tlsVersionName(version)

	switch version {
	case tls.VersionTLS10:
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevHigh,
			Title:       "Server negotiated TLS 1.0",
			Description: "TLS 1.0 is deprecated (RFC 8996) and has known vulnerabilities including BEAST and POODLE",
			Evidence:    fmt.Sprintf("Negotiated version: %s", versionName),
			CWE:         "CWE-326",
			CVSS:        7.4,
			Remediation: "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ minimum",
		})
	case tls.VersionTLS11:
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevHigh,
			Title:       "Server negotiated TLS 1.1",
			Description: "TLS 1.1 is deprecated (RFC 8996) and no longer considered secure",
			Evidence:    fmt.Sprintf("Negotiated version: %s", versionName),
			CWE:         "CWE-326",
			CVSS:        7.4,
			Remediation: "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ minimum",
		})
	case tls.VersionTLS12:
		findings = append(findings, engine.Finding{
			Module:   t.Name(),
			Severity: engine.SevInfo,
			Title:    "Server supports TLS 1.2",
			Evidence: fmt.Sprintf("Negotiated version: %s", versionName),
		})
	case tls.VersionTLS13:
		findings = append(findings, engine.Finding{
			Module:   t.Name(),
			Severity: engine.SevInfo,
			Title:    "Server supports TLS 1.3",
			Evidence: fmt.Sprintf("Negotiated version: %s", versionName),
		})
	}

	return findings
}

func (t *TLS) checkCertificate(cert *x509.Certificate, host string) []engine.Finding {
	var findings []engine.Finding
	now := time.Now()

	// Expiry checks
	if now.After(cert.NotAfter) {
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevCritical,
			Title:       "TLS certificate has expired",
			Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotAfter: %s (expired %d days ago)", cert.NotAfter.Format(time.RFC3339), int(now.Sub(cert.NotAfter).Hours()/24)),
			CWE:         "CWE-298",
			CVSS:        9.1,
			Remediation: "Renew the TLS certificate immediately",
		})
	} else {
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysLeft < 30 {
			findings = append(findings, engine.Finding{
				Module:      t.Name(),
				Severity:    engine.SevHigh,
				Title:       fmt.Sprintf("TLS certificate expires in %d days", daysLeft),
				Description: "Certificate is close to expiration and should be renewed soon",
				Evidence:    fmt.Sprintf("NotAfter: %s (%d days remaining)", cert.NotAfter.Format(time.RFC3339), daysLeft),
				CWE:         "CWE-298",
				CVSS:        5.3,
				Remediation: "Renew the TLS certificate before expiration. Consider automated renewal with Let's Encrypt/ACME",
			})
		}
	}

	// Not yet valid
	if now.Before(cert.NotBefore) {
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevCritical,
			Title:       "TLS certificate is not yet valid",
			Description: fmt.Sprintf("Certificate becomes valid on %s", cert.NotBefore.Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotBefore: %s", cert.NotBefore.Format(time.RFC3339)),
			CWE:         "CWE-298",
		})
	}

	// Self-signed check
	if cert.Issuer.CommonName == cert.Subject.CommonName && cert.IsCA {
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevHigh,
			Title:       "Self-signed certificate detected",
			Description: "The certificate is self-signed and will not be trusted by browsers",
			Evidence:    fmt.Sprintf("Issuer: %s, Subject: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
			CWE:         "CWE-295",
			CVSS:        6.5,
			Remediation: "Use a certificate from a trusted Certificate Authority (e.g. Let's Encrypt)",
		})
	}

	// Hostname verification
	if err := cert.VerifyHostname(host); err != nil {
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevHigh,
			Title:       "Certificate hostname mismatch",
			Description: fmt.Sprintf("Certificate does not match hostname '%s'", host),
			Evidence:    fmt.Sprintf("Subject: %s, SANs: %v, Error: %v", cert.Subject.CommonName, cert.DNSNames, err),
			CWE:         "CWE-297",
			CVSS:        7.4,
			Remediation: "Obtain a certificate that includes the correct hostname in the Subject Alternative Names",
		})
	}

	// Weak key size
	if cert.PublicKeyAlgorithm.String() == "RSA" {
		if key, ok := cert.PublicKey.(interface{ Size() int }); ok {
			bits := key.Size() * 8
			if bits < 2048 {
				findings = append(findings, engine.Finding{
					Module:      t.Name(),
					Severity:    engine.SevHigh,
					Title:       fmt.Sprintf("Weak RSA key size: %d bits", bits),
					Description: "RSA keys smaller than 2048 bits are considered insecure",
					Evidence:    fmt.Sprintf("RSA key size: %d bits", bits),
					CWE:         "CWE-326",
					Remediation: "Use RSA 2048-bit or higher, or switch to ECDSA P-256+",
				})
			}
		}
	}

	return findings
}

func (t *TLS) checkChain(state tls.ConnectionState) []engine.Finding {
	var findings []engine.Finding

	if len(state.PeerCertificates) == 1 && !state.PeerCertificates[0].IsCA {
		findings = append(findings, engine.Finding{
			Module:      t.Name(),
			Severity:    engine.SevMedium,
			Title:       "Incomplete certificate chain",
			Description: "Server sends only the leaf certificate without intermediate CA certificates",
			Evidence:    fmt.Sprintf("Chain length: %d certificate(s)", len(state.PeerCertificates)),
			CWE:         "CWE-295",
			Remediation: "Configure the server to send the full certificate chain including intermediate certificates",
		})
	}

	return findings
}

func (t *TLS) checkCipher(state tls.ConnectionState) []engine.Finding {
	var findings []engine.Finding

	suite := state.CipherSuite
	suiteName := tls.CipherSuiteName(suite)

	// Check for known insecure cipher suites
	for _, insecure := range tls.InsecureCipherSuites() {
		if insecure.ID == suite {
			findings = append(findings, engine.Finding{
				Module:      t.Name(),
				Severity:    engine.SevHigh,
				Title:       "Insecure cipher suite negotiated",
				Description: fmt.Sprintf("The server negotiated a cipher suite marked as insecure: %s", suiteName),
				Evidence:    fmt.Sprintf("Cipher: %s (0x%04x)", suiteName, suite),
				CWE:         "CWE-327",
				CVSS:        7.4,
				Remediation: "Disable insecure cipher suites. Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305)",
			})
			break
		}
	}

	// Check for weak cipher characteristics in the name
	weakPatterns := []struct {
		pattern string
		reason  string
	}{
		{"RC4", "RC4 is broken and prohibited by RFC 7465"},
		{"DES", "DES/3DES has a small block size vulnerable to Sweet32"},
		{"NULL", "NULL cipher provides no encryption"},
		{"EXPORT", "Export ciphers use intentionally weakened cryptography"},
		{"anon", "Anonymous cipher suites provide no authentication"},
	}

	for _, wp := range weakPatterns {
		if strings.Contains(suiteName, wp.pattern) {
			findings = append(findings, engine.Finding{
				Module:      t.Name(),
				Severity:    engine.SevHigh,
				Title:       fmt.Sprintf("Weak cipher suite: %s", suiteName),
				Description: wp.reason,
				Evidence:    suiteName,
				CWE:         "CWE-327",
				Remediation: "Disable weak cipher suites and use modern AEAD ciphers",
			})
		}
	}

	return findings
}

func (t *TLS) probeDeprecatedVersions(host string, timeout time.Duration) []engine.Finding {
	var findings []engine.Finding

	deprecated := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	addr := net.JoinHostPort(host, "443")
	dialer := &net.Dialer{Timeout: timeout}

	for _, d := range deprecated {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         d.version,
			MaxVersion:         d.version,
		})
		if err == nil {
			conn.Close()
			findings = append(findings, engine.Finding{
				Module:      t.Name(),
				Severity:    engine.SevHigh,
				Title:       fmt.Sprintf("Server accepts deprecated %s", d.name),
				Description: fmt.Sprintf("%s is deprecated and should be disabled. Server accepted a connection using this version.", d.name),
				Evidence:    fmt.Sprintf("Successfully connected with %s", d.name),
				CWE:         "CWE-326",
				CVSS:        7.4,
				Remediation: "Disable TLS 1.0 and 1.1. Set minimum version to TLS 1.2",
			})
		}
	}

	return findings
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}
