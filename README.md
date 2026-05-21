<div align="center">

# VX Security Scanner

**Fast, open-source web application security scanner & vulnerability assessment tool**

Detect XSS, SQL injection, CORS misconfig, TLS issues, open redirects, path traversal, exposed secrets, and more -- in seconds.

```
  ██╗   ██╗██╗  ██╗
  ██║   ██║╚██╗██╔╝
  ██║   ██║ ╚███╔╝  Security Scanner
  ╚██╗ ██╔╝ ██╔██╗
   ╚████╔╝ ██╔╝ ██╗
    ╚═══╝  ╚═╝  ╚═╝
```

[![Go](https://img.shields.io/badge/Toolchain-Go_1.26.3+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/MakFly/vx/actions/workflows/ci.yml/badge.svg)](https://github.com/MakFly/vx/actions)
[![GitHub release](https://img.shields.io/github/v/release/MakFly/vx?include_prereleases&label=release)](https://github.com/MakFly/vx/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/MakFly/vx)](https://goreportcard.com/report/github.com/MakFly/vx)

[Quick Start](#quick-start) | [Modules](#remote-scan----16-modules) | [CI/CD](#cicd-integration) | [Install](#quick-start)

</div>

---

## Why VX?

Most web security scanners are slow (Puppeteer-based), bloated (heavy runtimes), or limited to a single language. **VX** is a modern alternative:

- **Blazing fast** -- full 16-module scan in **~7 seconds** (parallel goroutines)
- **Single binary** -- one `go build`, deploy anywhere, zero runtime dependencies
- **Dual mode** -- black-box penetration testing (remote) + white-box code audit (local)
- **Multi-language SAST** -- audits PHP, TypeScript, JavaScript, Go, Python, Java, Rust
- **CI/CD native** -- GitHub Action, SARIF for Code Scanning, PR comments, score badges
- **Low false positives** -- smart SPA catch-all detection for Next.js, React, Vue, Angular, Nuxt
- **OWASP coverage** -- tests for Top 10 vulnerabilities: injection, XSS, broken auth, misconfig, and more

## Quick Start

Install: `curl -fsSL https://raw.githubusercontent.com/MakFly/vx/main/install.sh | bash`

```bash
# Remote scan (black-box)
vx scan https://example.com

# Include intrusive modules (portscan, subdomain, login)
vx scan https://example.com --aggressive

# Local audit (white-box)
vx audit ./my-project

# Both at once
vx full ./my-project --url https://example.com

# Interactive mode
vx
```

## Remote Scan -- 16 Modules

Default scans skip the more intrusive `portscan`, `subdomain`, and `login` modules. Pass `--aggressive` to include them, or select them explicitly with `--modules`.

| Module | What it checks |
|--------|---------------|
| `headers` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `cookies` | HttpOnly, Secure, SameSite flags on all cookies |
| `tls` | TLS 1.0/1.1 deprecated versions, certificate expiry, self-signed, cipher suites |
| `cors` | Origin reflection, wildcard + credentials, null origin, dangerous methods |
| `xss` | Reflected XSS (5 payload types), dataLayer injection, DOM sinks |
| `sqli` | Error-based (MySQL/PgSQL/MSSQL/SQLite/Oracle) + time-based blind injection |
| `redirect` | Open redirect via 14 common parameters, meta refresh, protocol-relative URLs |
| `traversal` | Path traversal / LFI with 6 encoding variants (Linux + Windows) |
| `webservice` | API discovery, default keys, resource enumeration, PrestaShop/WordPress/REST |
| `discovery` | Tech fingerprint (20+), 27 sensitive paths, SPF/DMARC/DKIM, dangling CNAME |
| `info` | Tokens, secrets, debug info, HTML comments, emails, tracking IDs |
| `portscan` | 20 common TCP ports with service identification |
| `subdomain` | 80+ subdomain enumeration with HTTP/HTTPS probing |
| `login` | Form discovery, CSRF tokens, rate limiting, autocomplete, HTTPS |
| `httpmethods` | OPTIONS, PUT, DELETE, TRACE (XST) with SPA catch-all detection |
| `jsdiscovery` | API endpoint extraction from JavaScript bundles, unauthenticated access testing |

## Local Audit -- 5 Modules

| Module | Languages | What it checks |
|--------|-----------|---------------|
| `secrets` | All | 12 patterns (AWS, Stripe, GitHub, JWT, private keys...) + Shannon entropy detection |
| `env-files` | All | .env in .gitignore, secrets in .env.example, git-tracked env files |
| `dependencies` | npm, Composer, Go, pip, Cargo, Maven | CVE lookup via [OSV.dev](https://osv.dev) API |
| `code-vulns` | PHP, JS/TS, Go, Python, Java | SQLi, XSS, eval, command injection, weak crypto patterns |
| `auth-config` | Next.js, Express, Symfony, Laravel | CORS wildcard, debug mode, session config, framework-specific checks |

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal | *(default)* | Human-readable with colors and severity grouping |
| JSON | `--json` | Machine-readable, pipe to `jq` |
| HTML | `--html report.html` | Standalone dark-themed report with score gauge |
| SARIF | `--sarif results.sarif` | GitHub Code Scanning / GitLab SAST |
| Markdown | `--markdown report.md` | PR comments with score delta |
| Badge | `--badge badge.json` | shields.io endpoint for README badges |

## Scoring

Every finding has a severity that impacts the score:

| Severity | Points deducted | Example |
|----------|----------------|---------|
| Critical | -15 | Exposed .env, unauthenticated API, LFI confirmed |
| High | -8 | Missing CSP, deprecated TLS, reflected XSS |
| Medium | -3 | Missing X-Frame-Options, CORS misconfiguration |
| Low | -1 | Server header disclosure, SPF softfail |
| Info | 0 | Technology fingerprint, open ports |

**Grades**: A (90-100) -- B (75-89) -- C (60-74) -- D (40-59) -- F (0-39)

## CI/CD Integration

### GitHub Action

```yaml
name: Security
on: [push, pull_request]

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MakFly/vx@v1
        with:
          url: 'https://your-app.com'
          min-score: 70
```

The action automatically:
- Posts/updates a PR comment with score, severity counts, and top findings
- Uploads SARIF to GitHub Code Scanning (Security tab)
- Commits a badge JSON on push to default branch
- Fails the workflow if score drops below threshold

### CLI in CI

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/MakFly/vx/main/install.sh | bash

# Run with threshold
vx scan https://your-app.com --ci --min-score 75 --sarif results.sarif

# Exit code 1 if score < min-score
```

## Scan History

```bash
# List all saved scans
vx history list

# Show details of a saved scan
vx history show 2026-04-11_02-24-22_www-iautos-fr.json

# Compare two scans (score delta, new/fixed findings)
vx history compare scan-before.json scan-after.json

# Export as HTML report
vx history export scan.json --html report.html
```

All scans are automatically saved to `~/.vx/scans/`.

## Configuration

Create `vx.yaml` in your project root:

```yaml
target: https://your-app.com
threads: 10
timeout: 15

modules: []  # empty = safe default modules; use --aggressive for intrusive modules

ci:
  min-score: 70
  fail-on-score: true

output:
  sarif: vx-results.sarif
  badge: .github/vx-badge.json

ignore:
  - "Firebase API Key"
  - "Supabase Anon Key"
```

Exclude files from local audit with `.vxignore` (gitignore syntax).

## SPA False Positive Detection

VX automatically detects SPA framework catch-all pages (Next.js, React, Vue, Angular, Nuxt) that return HTTP 200 for any route. This prevents false positives that plague other scanners:

- XSS payloads reflected in a catch-all page are not reported as vulnerabilities
- PUT/DELETE returning 200 on a catch-all are downgraded to INFO
- API endpoint probing ignores HTML catch-all responses

## Building

```bash
# Development
go build -o vx ./main.go

# Production (stripped)
go build -ldflags "-s -w" -o vx ./main.go

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o vx-linux-amd64 ./main.go
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o vx-darwin-arm64 ./main.go
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o vx.exe ./main.go
```

```bash
# Run tests
make test

# Lint
make lint

# Build + test + lint
make all
```

## Project Structure

```
vx/
├── cmd/                    # CLI commands (cobra)
│   ├── scan.go             # vx scan <url>
│   ├── audit.go            # vx audit <path>
│   ├── full.go             # vx full <path> --url <url>
│   ├── history.go          # vx history list|show|compare|export
│   └── interactive.go      # vx (no args = interactive menu)
├── pkg/
│   ├── engine/             # Core: Module interface, Config, Finding, Score
│   ├── modules/            # 16 remote scan modules
│   ├── local/              # 5 local audit modules
│   ├── report/             # Output: terminal, HTML, SARIF, badge, markdown
│   ├── config/             # vx.yaml parser
│   └── history/            # Scan history persistence
├── action.yml              # GitHub Action definition
├── Makefile                # Build, test, lint targets
└── .github/workflows/      # CI + security scan + release
```

## How VX Compares

| Feature | VX | Nuclei | ZAP | Nikto | VICE |
|---------|:--:|:------:|:---:|:-----:|:----:|
| Single binary | Yes | Yes | No (Java) | No (Perl) | No (Node) |
| Scan speed | ~7s | Varies | Minutes | Minutes | ~2min |
| Local code audit (SAST) | Yes | No | No | No | JS only |
| Multi-language SAST | 7 langs | No | No | No | No |
| SPA false-positive filter | Yes | No | No | No | No |
| GitHub Action | Yes | Yes | Yes | No | Yes |
| SARIF output | Yes | Yes | No | No | Yes |
| Dependency CVE check | Yes (OSV.dev) | No | No | No | npm only |
| SQLi + XSS testing | Yes | Yes | Yes | Limited | Yes |
| Score & grading | Yes (0-100, A-F) | No | Risk levels | No | Yes |
| TLS audit | Yes | No | Yes | Yes | No |
| Subdomain enum | Yes | No | No | No | Yes |
| Port scanning | Yes | No | No | No | Yes |

## Use Cases

- **Penetration testing** -- run `vx scan` against staging/production targets
- **CI/CD security gate** -- block merges if security score drops below threshold
- **Code review** -- run `vx audit` to catch hardcoded secrets, SQLi patterns, XSS sinks
- **Compliance** -- generate SARIF reports for security audits and compliance documentation
- **Bug bounty** -- quickly enumerate attack surface (subdomains, ports, JS endpoints, APIs)
- **DevSecOps** -- integrate into your pipeline with the GitHub Action

## Legal

VX displays a legal disclaimer on first run. Only scan systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

```bash
git clone https://github.com/MakFly/vx.git
cd vx
make all  # build + test + lint
```

## License

[MIT](LICENSE)

---

<div align="center">

**If VX helped you, consider giving it a star** -- it helps others discover the project.

</div>
