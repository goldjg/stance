package eval

import "github.com/goldjg/stance/internal/core/rules"

type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

type Finding struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Severity     rules.Severity `json:"severity"`
	Status       Status         `json:"status"`
	Summary      string         `json:"summary"`
	MatchedItems []string       `json:"matched_items,omitempty"`
}

type Result struct {
	Findings []Finding `json:"findings"`
}
