package local

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakFly/vx/pkg/engine"
)

// LocalModule defines the interface for local audit modules.
type LocalModule interface {
	Name() string
	Description() string
	Run(cfg *AuditConfig) ([]engine.Finding, error)
}

// AuditConfig holds configuration for local audit runs.
type AuditConfig struct {
	Path      string
	Languages []string // auto-detected: "php", "typescript", "javascript", "go", "java", "python", "rust"
	Verbose   bool
}

// languageIndicator maps file markers to language names.
var languageIndicators = map[string]string{
	"package.json":    "javascript",
	"tsconfig.json":   "typescript",
	"composer.json":   "php",
	"go.mod":          "go",
	"pom.xml":         "java",
	"build.gradle":    "java",
	"Cargo.toml":      "rust",
	"requirements.txt": "python",
	"Pipfile":         "python",
	"pyproject.toml":  "python",
	"setup.py":        "python",
}

// DetectLanguages scans the project root for known marker files.
func DetectLanguages(path string) []string {
	seen := make(map[string]bool)
	var langs []string

	for marker, lang := range languageIndicators {
		target := filepath.Join(path, marker)
		if _, err := os.Stat(target); err == nil {
			if !seen[lang] {
				seen[lang] = true
				langs = append(langs, lang)
			}
		}
	}

	// If we found javascript but also typescript, keep both
	// If tsconfig exists alongside package.json, typescript is primary
	return langs
}

// HasLanguage checks if a language is in the detected set.
func HasLanguage(cfg *AuditConfig, lang string) bool {
	for _, l := range cfg.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// ReadVxIgnore parses a .vxignore file and returns the patterns.
func ReadVxIgnore(path string) []string {
	ignoreFile := filepath.Join(path, ".vxignore")
	f, err := os.Open(ignoreFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// WalkFiles walks the file tree rooted at root, skipping ignored directories
// and returning files matching the given extensions.
func WalkFiles(root string, ignore []string, extensions []string) ([]string, error) {
	// Default directories to always skip
	defaultIgnore := []string{
		".git", "node_modules", "vendor", ".venv", "__pycache__",
		"target", "dist", "build", ".next", ".nuxt",
	}
	allIgnore := append(defaultIgnore, ignore...)

	extSet := make(map[string]bool, len(extensions))
	for _, ext := range extensions {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		extSet[ext] = true
	}

	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		if info.IsDir() {
			base := info.Name()
			for _, ig := range allIgnore {
				if matchIgnorePattern(base, ig) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Filter by extension if specified
		if len(extSet) > 0 {
			ext := filepath.Ext(path)
			if !extSet[ext] {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// matchIgnorePattern matches a directory name against an ignore pattern.
func matchIgnorePattern(name, pattern string) bool {
	if matched, _ := filepath.Match(pattern, name); matched {
		return true
	}
	return name == pattern
}

// ShannonEntropy computes the Shannon entropy of a string.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// IsTestFile checks if a file path looks like a test file.
func IsTestFile(path string) bool {
	lower := strings.ToLower(path)
	testPatterns := []string{
		"/test/", "/tests/", "/__tests__/",
		"/spec/", "/specs/",
		"/fixture/", "/fixtures/",
		"_test.go", ".test.", ".spec.",
		"/testdata/", "/mock/", "/mocks/",
	}
	for _, p := range testPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
