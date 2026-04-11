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
	Score    int      `json:"score"`
	Grade    Grade    `json:"grade"`
	Findings []Finding `json:"findings"`
	Summary  map[Severity]int `json:"summary"`
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

	var grade Grade
	switch {
	case score >= 90:
		grade = GradeA
	case score >= 75:
		grade = GradeB
	case score >= 60:
		grade = GradeC
	case score >= 40:
		grade = GradeD
	default:
		grade = GradeF
	}

	return ScoreResult{
		Score:    score,
		Grade:    grade,
		Findings: findings,
		Summary:  summary,
	}
}
