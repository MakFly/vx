package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

// ScanEntry represents metadata for a saved scan.
type ScanEntry struct {
	Filename string        `json:"filename"`
	Target   string        `json:"target"`
	Date     time.Time     `json:"date"`
	Score    int           `json:"score"`
	Grade    engine.Grade  `json:"grade"`
	Findings int           `json:"findings"`
	Duration time.Duration `json:"duration"`
}

// ScanDiff represents the difference between two scans.
type ScanDiff struct {
	ScoreA        int              `json:"score_a"`
	ScoreB        int              `json:"score_b"`
	Delta         int              `json:"delta"`
	NewFindings   []engine.Finding `json:"new_findings"`
	FixedFindings []engine.Finding `json:"fixed_findings"`
}

// StoredScan is the full JSON structure saved to disk.
type StoredScan struct {
	Target   string             `json:"target"`
	Date     time.Time          `json:"date"`
	Duration time.Duration      `json:"duration"`
	Result   engine.ScoreResult `json:"result"`
}

// dir returns the scan history directory, creating it if needed.
func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	d := filepath.Join(home, ".vx", "scans")
	if err := os.MkdirAll(d, 0755); err != nil {
		return "", fmt.Errorf("create history dir: %w", err)
	}
	return d, nil
}

// SaveScan persists a scan result to ~/.vx/scans/.
func SaveScan(result engine.ScoreResult, target string, duration time.Duration) error {
	d, err := dir()
	if err != nil {
		return err
	}

	now := time.Now()
	hostname := extractHostname(target)
	filename := fmt.Sprintf("%s_%s.json", now.Format("2006-01-02_15-04-05"), hostname)

	stored := StoredScan{
		Target:   target,
		Date:     now,
		Duration: duration,
		Result:   result,
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}

	return os.WriteFile(filepath.Join(d, filename), data, 0644)
}

// ListScans returns all saved scans sorted by date (newest first).
func ListScans() ([]ScanEntry, error) {
	d, err := dir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(d)
	if err != nil {
		return nil, fmt.Errorf("read history dir: %w", err)
	}

	var scans []ScanEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(d, entry.Name()))
		if err != nil {
			continue
		}

		var stored StoredScan
		if err := json.Unmarshal(data, &stored); err != nil {
			continue
		}

		scans = append(scans, ScanEntry{
			Filename: entry.Name(),
			Target:   stored.Target,
			Date:     stored.Date,
			Score:    stored.Result.Score,
			Grade:    stored.Result.Grade,
			Findings: len(stored.Result.Findings),
			Duration: stored.Duration,
		})
	}

	sort.Slice(scans, func(i, j int) bool {
		return scans[i].Date.After(scans[j].Date)
	})

	return scans, nil
}

// LoadScan loads a full scan result from a filename.
func LoadScan(filename string) (*StoredScan, error) {
	d, err := dir()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(d, filename))
	if err != nil {
		return nil, fmt.Errorf("read scan file: %w", err)
	}

	var stored StoredScan
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("unmarshal scan: %w", err)
	}

	return &stored, nil
}

// LoadScanResult loads only the ScoreResult from a saved scan.
func LoadScanResult(filename string) (*engine.ScoreResult, error) {
	stored, err := LoadScan(filename)
	if err != nil {
		return nil, err
	}
	return &stored.Result, nil
}

// ComparScans compares two saved scans and returns the diff.
func ComparScans(a, b string) (*ScanDiff, error) {
	scanA, err := LoadScanResult(a)
	if err != nil {
		return nil, fmt.Errorf("load scan A: %w", err)
	}

	scanB, err := LoadScanResult(b)
	if err != nil {
		return nil, fmt.Errorf("load scan B: %w", err)
	}

	// Build finding sets by title+module key
	setA := make(map[string]engine.Finding)
	for _, f := range scanA.Findings {
		setA[f.Module+":"+f.Title] = f
	}
	setB := make(map[string]engine.Finding)
	for _, f := range scanB.Findings {
		setB[f.Module+":"+f.Title] = f
	}

	var newFindings []engine.Finding
	for key, f := range setB {
		if _, ok := setA[key]; !ok {
			newFindings = append(newFindings, f)
		}
	}

	var fixedFindings []engine.Finding
	for key, f := range setA {
		if _, ok := setB[key]; !ok {
			fixedFindings = append(fixedFindings, f)
		}
	}

	return &ScanDiff{
		ScoreA:        scanA.Score,
		ScoreB:        scanB.Score,
		Delta:         scanB.Score - scanA.Score,
		NewFindings:   newFindings,
		FixedFindings: fixedFindings,
	}, nil
}

// extractHostname extracts the hostname from a URL for filenames.
func extractHostname(target string) string {
	host := target
	// Remove scheme
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	// Remove path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	// Sanitize for filename
	host = strings.ReplaceAll(host, ".", "-")
	return host
}
