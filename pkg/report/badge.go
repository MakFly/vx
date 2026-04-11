package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MakFly/vx/pkg/engine"
)

// shields.io endpoint badge JSON format

type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

func WriteBadge(result engine.ScoreResult, path string) error {
	badge := Badge{
		SchemaVersion: 1,
		Label:         "VX Security",
		Message:       fmt.Sprintf("%d/100 %s", result.Score, result.Grade),
		Color:         badgeColor(result.Grade),
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create badge file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(badge)
}

func badgeColor(g engine.Grade) string {
	switch g {
	case engine.GradeA:
		return "brightgreen"
	case engine.GradeB:
		return "green"
	case engine.GradeC:
		return "yellow"
	case engine.GradeD:
		return "orange"
	case engine.GradeF:
		return "red"
	}
	return "lightgrey"
}
