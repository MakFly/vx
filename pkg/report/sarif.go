package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/MakFly/vx/pkg/engine"
)

// SARIF 2.1.0 output for GitHub Code Scanning / GitLab SAST

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  sarifMessage      `json:"fullDescription,omitempty"`
	Help             sarifMessage      `json:"help,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Security string   `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func WriteSARIF(result engine.ScoreResult, path string) error {
	rules := make(map[string]sarifRule)
	var results []sarifResult

	for _, f := range result.Findings {
		ruleID := sarifRuleID(f)

		if _, exists := rules[ruleID]; !exists {
			rules[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Help:             sarifMessage{Text: f.Remediation},
				Properties: sarifRuleProperties{
					Tags:     buildTags(f),
					Security: fmt.Sprintf("%.1f", f.CVSS),
				},
			}
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: buildMessage(f)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: "index.html", // Remote scan — no specific file
						},
					},
				},
			},
		})
	}

	var ruleList []sarifRule
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "VX Security Scanner",
						Version:        "0.1.0",
						InformationURI: "https://github.com/MakFly/vx",
						Rules:          ruleList,
					},
				},
				Results: results,
			},
		},
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create SARIF file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifRuleID returns a stable rule identifier derived from the finding's module,
// CWE, and title. Two scans of the same finding always produce the same ID.
func sarifRuleID(f engine.Finding) string {
	if f.CWE != "" {
		return fmt.Sprintf("VX-%s-%s", f.Module, f.CWE)
	}
	sum := sha256.Sum256([]byte(f.Module + ":" + f.Title))
	return fmt.Sprintf("VX-%s-%s", f.Module, hex.EncodeToString(sum[:4]))
}

func sarifLevel(s engine.Severity) string {
	switch s {
	case engine.SevCritical, engine.SevHigh:
		return "error"
	case engine.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildTags(f engine.Finding) []string {
	tags := []string{"security", f.Module}
	if f.CWE != "" {
		tags = append(tags, f.CWE)
	}
	return tags
}

func buildMessage(f engine.Finding) string {
	msg := f.Description
	if f.Evidence != "" {
		msg += "\n\nEvidence: " + f.Evidence
	}
	if f.Remediation != "" {
		msg += "\n\nRemediation: " + f.Remediation
	}
	return msg
}
