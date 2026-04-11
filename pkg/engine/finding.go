package engine

import "fmt"

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

func (s Severity) Points() int {
	switch s {
	case SevCritical:
		return 15
	case SevHigh:
		return 8
	case SevMedium:
		return 3
	case SevLow:
		return 1
	case SevInfo:
		return 0
	}
	return 0
}

type Finding struct {
	Module      string   `json:"module"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Module, f.Title)
}
