package engine

type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

type ScoreResult struct {
	Score    int              `json:"score"`
	Grade    Grade            `json:"grade"`
	Findings []Finding        `json:"findings"`
	Summary  map[Severity]int `json:"summary"`
	Partial  bool             `json:"partial,omitempty"`
	// Errors holds per-module errors encountered during the scan.
	// A non-empty Errors slice means the scan is partial.
	Errors []ModuleError `json:"errors,omitempty"`
}

func ComputeScore(findings []Finding) ScoreResult {
	score := 100
	summary := make(map[Severity]int)

	for _, f := range findings {
		score -= f.Severity.Points()
		summary[f.Severity]++
	}

	if score < 0 {
		score = 0
	}

	return ScoreResult{
		Score:    score,
		Grade:    GradeForScore(score),
		Findings: findings,
		Summary:  summary,
	}
}

func ComputePartialScore(findings []Finding, errors []ModuleError) ScoreResult {
	result := ComputeScore(findings)
	if len(errors) == 0 {
		return result
	}

	result.Partial = true
	result.Errors = errors
	if result.Score > 60 {
		result.Score = 60
		result.Grade = GradeForScore(result.Score)
	}
	return result
}

func GradeForScore(score int) Grade {
	switch {
	case score >= 90:
		return GradeA
	case score >= 75:
		return GradeB
	case score >= 60:
		return GradeC
	case score >= 40:
		return GradeD
	default:
		return GradeF
	}
}
