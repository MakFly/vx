package modules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

type Discovery struct{}

func (d *Discovery) Name() string        { return "discovery" }
func (d *Discovery) Description() string { return "Technology fingerprinting, sensitive paths, DNS recon" }

func (d *Discovery) Run(ctx context.Context, cfg *engine.Config) ([]engine.Finding, error) {
	client := newHTTPClient(cfg)
	resp, body, err := doGet(client, cfg.TargetURL, cfg.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var findings []engine.Finding

	// Tech fingerprinting
	findings = append(findings, d.fingerprint(resp, body, cfg)...)

	// Sensitive paths
	findings = append(findings, d.sensitivePaths(client, cfg)...)

	// DNS checks
	findings = append(findings, d.dnsChecks(cfg)...)

	return findings, nil
}

func (d *Discovery) fingerprint(resp *http.Response, body []byte, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding
	html := string(body)
	var techs []string

	patterns := map[string]*regexp.Regexp{
		"PrestaShop":  regexp.MustCompile(`(?i)prestashop|/modules/ps_|/themes/.*prestashop`),
		"WordPress":   regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`),
		"Drupal":      regexp.MustCompile(`(?i)drupal|sites/default/files`),
		"Magento":     regexp.MustCompile(`(?i)magento|/skin/frontend|mage/cookies`),
		"Shopify":     regexp.MustCompile(`(?i)cdn\.shopify\.com|shopify\.com`),
		"React":       regexp.MustCompile(`(?i)react\.production|__NEXT_DATA__|_next/static`),
		"Vue.js":      regexp.MustCompile(`(?i)vue\.runtime|__vue__|v-cloak`),
		"Angular":     regexp.MustCompile(`(?i)ng-version|angular\.min\.js`),
		"jQuery":      regexp.MustCompile(`(?i)jquery[.-]\d|jquery\.min\.js`),
		"Bootstrap":   regexp.MustCompile(`(?i)bootstrap\.min\.(css|js)`),
		"GTM":         regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`),
		"GA":          regexp.MustCompile(`(?i)google-analytics\.com|UA-\d+-\d+|G-[A-Z0-9]+`),
		"Facebook Pixel": regexp.MustCompile(`(?i)connect\.facebook\.net/.*fbevents|fbq\(`),
		"Crisp":       regexp.MustCompile(`(?i)crisp\.chat|crisp\.im`),
		"Hotjar":      regexp.MustCompile(`(?i)static\.hotjar\.com|hj\(`),
		"Cloudflare":  regexp.MustCompile(`(?i)cloudflare|cf-ray`),
		"Sendinblue":  regexp.MustCompile(`(?i)sibautomation\.com|sendinblue`),
		"Stripe":      regexp.MustCompile(`(?i)js\.stripe\.com|stripe\.js`),
		"reCAPTCHA":   regexp.MustCompile(`(?i)recaptcha/api|grecaptcha`),
		"LayerSlider": regexp.MustCompile(`(?i)layerslider`),
	}

	for name, re := range patterns {
		if re.MatchString(html) {
			techs = append(techs, name)
		}
	}

	// Check response headers too
	if strings.Contains(resp.Header.Get("X-Powered-By"), "PHP") {
		techs = append(techs, "PHP")
	}
	if resp.Header.Get("cf-ray") != "" {
		techs = append(techs, "Cloudflare CDN")
	}

	if len(techs) > 0 {
		findings = append(findings, engine.Finding{
			Module:      d.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("Detected %d technologies", len(techs)),
			Description: "Stack fingerprint from HTML and headers analysis",
			Evidence:    strings.Join(techs, ", "),
		})
	}

	// Count external scripts (supply chain surface)
	extScripts := regexp.MustCompile(`<script[^>]+src=["']https?://[^"']+["']`).FindAllString(html, -1)
	if len(extScripts) > 5 {
		findings = append(findings, engine.Finding{
			Module:      d.Name(),
			Severity:    engine.SevMedium,
			Title:       fmt.Sprintf("%d external scripts loaded — supply chain risk", len(extScripts)),
			Description: "Large number of third-party scripts increases the attack surface for supply chain attacks",
			Evidence:    fmt.Sprintf("%d external script tags detected", len(extScripts)),
			CWE:         "CWE-829",
			Remediation: "Audit and minimize third-party scripts. Use SRI (Subresource Integrity) hashes.",
		})
	}

	return findings
}

func (d *Discovery) sensitivePaths(client *http.Client, cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	paths := []struct {
		path     string
		name     string
		severity engine.Severity
	}{
		{"/.git/HEAD", "Git repository exposed", engine.SevCritical},
		{"/.env", "Environment file exposed", engine.SevCritical},
		{"/.svn/entries", "SVN repository exposed", engine.SevCritical},
		{"/wp-config.php.bak", "WordPress config backup", engine.SevCritical},
		{"/config/settings.inc.php", "PrestaShop config exposed", engine.SevCritical},
		{"/app/config/parameters.php", "Symfony parameters exposed", engine.SevCritical},
		{"/phpinfo.php", "PHP info page exposed", engine.SevHigh},
		{"/info.php", "PHP info page exposed", engine.SevHigh},
		{"/server-status", "Apache server-status exposed", engine.SevHigh},
		{"/server-info", "Apache server-info exposed", engine.SevHigh},
		{"/.htpasswd", "htpasswd file exposed", engine.SevCritical},
		{"/.htaccess", "htaccess file exposed", engine.SevMedium},
		{"/debug", "Debug endpoint exposed", engine.SevHigh},
		{"/elmah.axd", "ELMAH error log exposed", engine.SevHigh},
		{"/web.config", "IIS config exposed", engine.SevHigh},
		{"/crossdomain.xml", "Flash crossdomain policy", engine.SevLow},
		{"/robots.txt", "Robots.txt", engine.SevInfo},
		{"/.well-known/security.txt", "Security.txt", engine.SevInfo},
		{"/security.txt", "Security.txt", engine.SevInfo},
		{"/sitemap.xml", "Sitemap", engine.SevInfo},
		{"/backup.sql", "SQL backup exposed", engine.SevCritical},
		{"/dump.sql", "SQL dump exposed", engine.SevCritical},
		{"/database.sql", "Database export exposed", engine.SevCritical},
		{"/.DS_Store", "macOS metadata exposed", engine.SevLow},
		{"/Thumbs.db", "Windows thumbnail cache exposed", engine.SevLow},
		{"/composer.json", "Composer manifest exposed", engine.SevLow},
		{"/package.json", "NPM manifest exposed", engine.SevLow},
	}

	noRedirectClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, p := range paths {
		url := strings.TrimRight(cfg.TargetURL, "/") + p.path
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", cfg.UserAgent)

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 && p.severity >= engine.SevLow {
			findings = append(findings, engine.Finding{
				Module:      d.Name(),
				Severity:    p.severity,
				Title:       p.name,
				Description: fmt.Sprintf("%s is accessible (HTTP %d)", p.path, resp.StatusCode),
				Evidence:    fmt.Sprintf("GET %s → %d", p.path, resp.StatusCode),
				CWE:         "CWE-538",
				Remediation: fmt.Sprintf("Block access to %s via server configuration", p.path),
			})
		}

		// .git 403 = exists but blocked (still info)
		if p.path == "/.git/HEAD" && resp.StatusCode == 403 {
			findings = append(findings, engine.Finding{
				Module:      d.Name(),
				Severity:    engine.SevInfo,
				Title:       "Git directory exists but access denied",
				Description: ".git/HEAD returns 403 — directory exists on server but is blocked",
				Evidence:    fmt.Sprintf("GET /.git/HEAD → %d", resp.StatusCode),
			})
		}

		// Security.txt missing
		if p.path == "/.well-known/security.txt" && resp.StatusCode == 404 {
			findings = append(findings, engine.Finding{
				Module:      d.Name(),
				Severity:    engine.SevLow,
				Title:       "No security.txt found",
				Description: "No vulnerability disclosure policy file at /.well-known/security.txt",
				CWE:         "CWE-1059",
				Remediation: "Create a security.txt file per RFC 9116 at /.well-known/security.txt",
			})
		}
	}

	return findings
}

func (d *Discovery) dnsChecks(cfg *engine.Config) []engine.Finding {
	var findings []engine.Finding

	host := extractHost(cfg.TargetURL)
	if host == "" {
		return findings
	}

	// Strip www. for domain-level checks
	domain := strings.TrimPrefix(host, "www.")

	// SPF check
	txts, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				if strings.Contains(txt, "~all") {
					findings = append(findings, engine.Finding{
						Module:      d.Name(),
						Severity:    engine.SevLow,
						Title:       "SPF uses softfail (~all) instead of hardfail (-all)",
						Description: "Spoofed emails are marked but not rejected. Use -all for strict enforcement.",
						Evidence:    txt,
						CWE:         "CWE-290",
						Remediation: "Change ~all to -all in your SPF record",
					})
				}
				if strings.Contains(txt, "+all") {
					findings = append(findings, engine.Finding{
						Module:      d.Name(),
						Severity:    engine.SevHigh,
						Title:       "SPF allows all senders (+all)",
						Description: "SPF record allows any server to send email for this domain",
						Evidence:    txt,
						CWE:         "CWE-290",
						Remediation: "Change +all to -all and list authorized senders",
					})
				}
			}
		}

		// DMARC check
		dmarcs, err := net.LookupTXT("_dmarc." + domain)
		hasDMARC := false
		if err == nil {
			for _, txt := range dmarcs {
				if strings.HasPrefix(txt, "v=DMARC1") {
					hasDMARC = true
					if strings.Contains(txt, "p=none") {
						findings = append(findings, engine.Finding{
							Module:      d.Name(),
							Severity:    engine.SevLow,
							Title:       "DMARC policy set to none (monitoring only)",
							Description: "DMARC is configured but not enforcing. Emails failing DMARC are still delivered.",
							Evidence:    txt,
							CWE:         "CWE-290",
							Remediation: "Change DMARC policy to p=quarantine or p=reject",
						})
					}
				}
			}
		}
		if !hasDMARC {
			findings = append(findings, engine.Finding{
				Module:      d.Name(),
				Severity:    engine.SevMedium,
				Title:       "No DMARC record found",
				Description: "No DMARC DNS record at _dmarc." + domain,
				CWE:         "CWE-290",
				Remediation: "Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@" + domain,
			})
		}
	}

	// DKIM check — probe common selectors
	selectors := []string{"default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "brevo"}
	var foundSelectors []string
	for _, sel := range selectors {
		dkimHost := sel + "._domainkey." + domain
		recs, err := net.LookupTXT(dkimHost)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			if strings.Contains(rec, "v=DKIM1") {
				foundSelectors = append(foundSelectors, sel)
				break
			}
		}
	}
	if len(foundSelectors) == 0 {
		findings = append(findings, engine.Finding{
			Module:      d.Name(),
			Severity:    engine.SevMedium,
			Title:       "No DKIM records found",
			Description: fmt.Sprintf("None of %d common DKIM selectors resolved for %s", len(selectors), domain),
			CWE:         "CWE-290",
			Remediation: "Configure DKIM signing for your mail provider and publish the public key as a TXT record",
		})
	} else {
		findings = append(findings, engine.Finding{
			Module:      d.Name(),
			Severity:    engine.SevInfo,
			Title:       fmt.Sprintf("DKIM configured (%d selector(s) found)", len(foundSelectors)),
			Description: "DKIM public keys found for domain",
			Evidence:    "Selectors: " + strings.Join(foundSelectors, ", "),
		})
	}

	// Dangling CNAME detection — check main domain and www
	danglingServices := map[string]string{
		".github.io":                        "GitHub Pages",
		".herokuapp.com":                    "Heroku",
		".s3.amazonaws.com":                 "AWS S3",
		".s3-website-":                      "AWS S3 Website",
		".myshopify.com":                    "Shopify",
		".netlify.app":                      "Netlify",
		".vercel.app":                       "Vercel",
	}
	cnameTargets := []string{domain, "www." + domain}
	for _, target := range cnameTargets {
		cname, err := net.LookupCNAME(target)
		if err != nil || cname == "" || cname == target+"." {
			continue
		}
		cname = strings.TrimSuffix(cname, ".")

		// Check if the CNAME points to a known service
		serviceName := ""
		for suffix, name := range danglingServices {
			if strings.HasSuffix(cname, suffix) || strings.Contains(cname, suffix) {
				serviceName = name
				break
			}
		}
		if serviceName == "" {
			continue
		}

		// Check if the CNAME target actually resolves
		_, err = net.LookupHost(cname)
		if err != nil {
			findings = append(findings, engine.Finding{
				Module:      d.Name(),
				Severity:    engine.SevHigh,
				Title:       "Dangling CNAME — potential subdomain takeover",
				Description: fmt.Sprintf("%s has a CNAME to %s (%s) but the target does not resolve", target, cname, serviceName),
				Evidence:    fmt.Sprintf("%s → CNAME %s (unresolvable)", target, cname),
				CWE:         "CWE-284",
				Remediation: "Remove the dangling CNAME record or reclaim the service endpoint",
			})
		}
	}

	return findings
}

func extractHost(rawURL string) string {
	s := rawURL
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.Split(s, "/")[0]
	s = strings.Split(s, ":")[0]
	return s
}
