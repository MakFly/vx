package local

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// CodeVulns scans source code for common vulnerability patterns.
type CodeVulns struct{}

func (c *CodeVulns) Name() string        { return "code-vulns" }
func (c *CodeVulns) Description() string { return "Detect common code vulnerability patterns" }

// vulnRule defines a regex-based vulnerability detection rule.
type vulnRule struct {
	Language    string
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Remediation string
	Severity    engine.Severity
	CWE         string
	CVSS        float64
}

var phpRules = []vulnRule{
	{
		Language:    "php",
		Pattern:     regexp.MustCompile(`(?:mysql_query|mysqli_query)\s*\(\s*.*\$`),
		Title:       "SQL injection (variable in query)",
		Description: "Raw variable interpolation in SQL query function call.",
		Remediation: "Use prepared statements with parameter binding.",
		Severity:    engine.SevCritical,
		CWE:         "CWE-89",
		CVSS:        9.8,
	},
	{
		Language:    "php",
		Pattern:     regexp.MustCompile(`\b(?:eval|system|exec|passthru|shell_exec)\s*\(`),
		Title:       "Command injection risk",
		Description: "Use of dangerous function that can execute arbitrary commands.",
		Remediation: "Avoid eval/system/exec. Use escapeshellarg() if shell commands are required.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-78",
		CVSS:        8.5,
	},
	{
		Language:    "php",
		Pattern:     regexp.MustCompile(`(?:md5|sha1)\s*\(\s*\$.*(?:password|passwd|pwd)`),
		Title:       "Weak password hashing (MD5/SHA1)",
		Description: "Using MD5 or SHA1 for password hashing is cryptographically weak.",
		Remediation: "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-328",
		CVSS:        7.5,
	},
	{
		Language:    "php",
		Pattern:     regexp.MustCompile(`(?:echo|print)\s+.*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`),
		Title:       "Reflected XSS (unsanitized output)",
		Description: "User input from superglobals output directly without htmlspecialchars().",
		Remediation: "Wrap output with htmlspecialchars($var, ENT_QUOTES, 'UTF-8').",
		Severity:    engine.SevHigh,
		CWE:         "CWE-79",
		CVSS:        7.5,
	},
	{
		Language:    "php",
		Pattern:     regexp.MustCompile(`FILTER_SANITIZE_STRING`),
		Title:       "Deprecated FILTER_SANITIZE_STRING",
		Description: "FILTER_SANITIZE_STRING is deprecated in PHP 8.1+ and provides inconsistent sanitization.",
		Remediation: "Use htmlspecialchars() or FILTER_SANITIZE_SPECIAL_CHARS instead.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-79",
		CVSS:        5.0,
	},
}

var jsRules = []vulnRule{
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`dangerouslySetInnerHTML`),
		Title:       "XSS sink: dangerouslySetInnerHTML",
		Description: "React dangerouslySetInnerHTML bypasses XSS protection.",
		Remediation: "Avoid dangerouslySetInnerHTML. Use DOMPurify.sanitize() if HTML rendering is necessary.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-79",
		CVSS:        6.0,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`\beval\s*\(`),
		Title:       "Code injection: eval()",
		Description: "eval() executes arbitrary code and is a code injection vector.",
		Remediation: "Replace eval() with safe alternatives like JSON.parse() or Function constructors with validated input.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-94",
		CVSS:        8.0,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`new\s+Function\s*\(`),
		Title:       "Code injection: new Function()",
		Description: "new Function() dynamically compiles code from strings.",
		Remediation: "Avoid new Function() with dynamic input.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-94",
		CVSS:        8.0,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile("(?:SELECT|INSERT|UPDATE|DELETE).*`.*\\$\\{"),
		Title:       "SQL injection via template literal",
		Description: "SQL query built with template literal interpolation.",
		Remediation: "Use parameterized queries or an ORM.",
		Severity:    engine.SevCritical,
		CWE:         "CWE-89",
		CVSS:        9.8,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
		Title:       "DOM XSS: innerHTML assignment",
		Description: "Setting innerHTML with dynamic content enables DOM-based XSS.",
		Remediation: "Use textContent for text, or DOMPurify.sanitize() before innerHTML.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-79",
		CVSS:        6.0,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`document\.write\s*\(`),
		Title:       "DOM XSS: document.write()",
		Description: "document.write() with dynamic content is a DOM XSS vector.",
		Remediation: "Use DOM manipulation methods (createElement, appendChild) instead.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-79",
		CVSS:        6.0,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`child_process\.exec\s*\(`),
		Title:       "Command injection: child_process.exec()",
		Description: "child_process.exec() with variable arguments enables command injection.",
		Remediation: "Use child_process.execFile() with explicit arguments array.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-78",
		CVSS:        8.5,
	},
	{
		Language:    "javascript",
		Pattern:     regexp.MustCompile(`crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)`),
		Title:       "Weak cryptographic hash",
		Description: "MD5/SHA1 are cryptographically broken for security purposes.",
		Remediation: "Use SHA-256 or stronger: crypto.createHash('sha256').",
		Severity:    engine.SevMedium,
		CWE:         "CWE-328",
		CVSS:        5.0,
	},
}

var goRules = []vulnRule{
	{
		Language:    "go",
		Pattern:     regexp.MustCompile(`fmt\.Sprintf\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)`),
		Title:       "SQL injection via fmt.Sprintf",
		Description: "Building SQL queries with fmt.Sprintf enables SQL injection.",
		Remediation: "Use parameterized queries with database/sql: db.Query(\"SELECT ... WHERE id = $1\", id).",
		Severity:    engine.SevCritical,
		CWE:         "CWE-89",
		CVSS:        9.8,
	},
	{
		Language:    "go",
		Pattern:     regexp.MustCompile(`exec\.Command\s*\([^")]+`),
		Title:       "Command injection: exec.Command with variable",
		Description: "exec.Command with variable arguments can enable command injection.",
		Remediation: "Validate and sanitize all arguments. Avoid passing user input to exec.Command.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-78",
		CVSS:        8.5,
	},
	{
		Language:    "go",
		Pattern:     regexp.MustCompile(`(?:md5|sha1)\.New\s*\(\s*\)`),
		Title:       "Weak cryptographic hash (MD5/SHA1)",
		Description: "MD5/SHA1 are cryptographically broken for security purposes.",
		Remediation: "Use sha256.New() from crypto/sha256.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-328",
		CVSS:        5.0,
	},
	{
		Language:    "go",
		Pattern:     regexp.MustCompile(`http\.ListenAndServe\s*\(`),
		Title:       "HTTP without TLS",
		Description: "http.ListenAndServe serves traffic without encryption.",
		Remediation: "Use http.ListenAndServeTLS() or place behind a TLS-terminating reverse proxy.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-319",
		CVSS:        5.0,
	},
}

var pythonRules = []vulnRule{
	{
		Language:    "python",
		Pattern:     regexp.MustCompile(`(?:os\.system|subprocess\.call)\s*\(\s*(?:f['""]|['""].*%|.*\.format)`),
		Title:       "Command injection via string interpolation",
		Description: "Shell command built with string interpolation enables command injection.",
		Remediation: "Use subprocess.run() with a list of arguments and shell=False.",
		Severity:    engine.SevCritical,
		CWE:         "CWE-78",
		CVSS:        9.8,
	},
	{
		Language:    "python",
		Pattern:     regexp.MustCompile(`\b(?:eval|exec)\s*\(`),
		Title:       "Code injection: eval()/exec()",
		Description: "eval()/exec() execute arbitrary Python code.",
		Remediation: "Avoid eval/exec. Use ast.literal_eval() for safe evaluation of literals.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-94",
		CVSS:        8.0,
	},
	{
		Language:    "python",
		Pattern:     regexp.MustCompile(`cursor\.execute\s*\(\s*(?:f['""]|['""].*%)`),
		Title:       "SQL injection via string formatting",
		Description: "SQL query built with f-string or % formatting in cursor.execute().",
		Remediation: "Use parameterized queries: cursor.execute(\"SELECT ... WHERE id = %s\", (id,)).",
		Severity:    engine.SevCritical,
		CWE:         "CWE-89",
		CVSS:        9.8,
	},
	{
		Language:    "python",
		Pattern:     regexp.MustCompile(`hashlib\.(?:md5|sha1)\s*\(`),
		Title:       "Weak cryptographic hash (MD5/SHA1)",
		Description: "MD5/SHA1 are cryptographically broken for password hashing.",
		Remediation: "Use hashlib.sha256() or bcrypt/argon2 for passwords.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-328",
		CVSS:        5.0,
	},
}

var javaRules = []vulnRule{
	{
		Language:    "java",
		Pattern:     regexp.MustCompile(`Statement\.executeQuery\s*\(\s*[^"]*\+`),
		Title:       "SQL injection via string concatenation",
		Description: "SQL query built with string concatenation in executeQuery().",
		Remediation: "Use PreparedStatement with parameterized queries.",
		Severity:    engine.SevCritical,
		CWE:         "CWE-89",
		CVSS:        9.8,
	},
	{
		Language:    "java",
		Pattern:     regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(`),
		Title:       "Command injection: Runtime.exec()",
		Description: "Runtime.exec() with dynamic input enables command injection.",
		Remediation: "Use ProcessBuilder with explicit argument list. Validate all inputs.",
		Severity:    engine.SevHigh,
		CWE:         "CWE-78",
		CVSS:        8.5,
	},
	{
		Language:    "java",
		Pattern:     regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)`),
		Title:       "Weak cryptographic hash (MD5)",
		Description: "MD5 is cryptographically broken for security purposes.",
		Remediation: "Use MessageDigest.getInstance(\"SHA-256\") or stronger.",
		Severity:    engine.SevMedium,
		CWE:         "CWE-328",
		CVSS:        5.0,
	},
}

// langExtensions maps languages to their file extensions.
var langExtensions = map[string][]string{
	"php":        {".php"},
	"javascript": {".js", ".jsx", ".mjs", ".cjs"},
	"typescript": {".ts", ".tsx"},
	"go":         {".go"},
	"python":     {".py"},
	"java":       {".java"},
	"rust":       {".rs"},
}

// langRules maps languages to their vulnerability rules.
var langRules = map[string][]vulnRule{
	"php":        phpRules,
	"javascript": jsRules,
	"typescript": jsRules, // TypeScript uses same patterns as JS
	"go":         goRules,
	"python":     pythonRules,
	"java":       javaRules,
}

func (c *CodeVulns) Run(cfg *AuditConfig) ([]engine.Finding, error) {
	ignore := ReadVxIgnore(cfg.Path)
	var findings []engine.Finding

	for _, lang := range cfg.Languages {
		rules, ok := langRules[lang]
		if !ok {
			continue
		}
		exts, ok := langExtensions[lang]
		if !ok {
			continue
		}

		files, err := WalkFiles(cfg.Path, ignore, exts)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "  [!] code-vulns: error walking %s files: %v\n", lang, err)
			}
			continue
		}

		for _, file := range files {
			fileFindings, err := scanFileForVulns(file, rules, cfg)
			if err != nil {
				if cfg.Verbose {
					fmt.Fprintf(os.Stderr, "  [!] code-vulns: error scanning %s: %v\n", file, err)
				}
				continue
			}
			findings = append(findings, fileFindings...)
		}
	}

	return findings, nil
}

func scanFileForVulns(path string, rules []vulnRule, cfg *AuditConfig) ([]engine.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	isTest := IsTestFile(path)

	var findings []engine.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comment lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				sev := rule.Severity
				if isTest && sev > engine.SevLow {
					sev = engine.SevLow
				}

				relPath := relativeToRoot(path, cfg.Path)
				findings = append(findings, engine.Finding{
					Module:      "code-vulns",
					Severity:    sev,
					Title:       rule.Title,
					Description: fmt.Sprintf("[%s] %s (file: %s, line: %d)", rule.Language, rule.Description, relPath, lineNum),
					Evidence:    truncateLine(line, 120),
					Remediation: rule.Remediation,
					CWE:         rule.CWE,
					CVSS:        rule.CVSS,
				})
			}
		}
	}

	return findings, scanner.Err()
}
