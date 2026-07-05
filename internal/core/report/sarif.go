package report

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/core/eval"
	"github.com/goldjg/stance/internal/core/result"
	"github.com/goldjg/stance/internal/core/rules"
)

type sarifRoot struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name,omitempty"`
	ShortDescription     sarifMultiformatMessage   `json:"shortDescription,omitempty"`
	DefaultConfiguration *sarifReportingDescriptor `json:"defaultConfiguration,omitempty"`
}

type sarifReportingDescriptor struct {
	Level string `json:"level,omitempty"`
}

type sarifResult struct {
	RuleID  string                  `json:"ruleId"`
	Level   string                  `json:"level,omitempty"`
	Message sarifMultiformatMessage `json:"message"`
}

type sarifMultiformatMessage struct {
	Text string `json:"text"`
}

func SARIF(doc result.Document) ([]byte, error) {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(doc.Findings))

	for _, finding := range doc.Findings {
		id := strings.TrimSpace(finding.RuleID)
		if id == "" {
			continue
		}
		if _, exists := rulesByID[id]; !exists {
			rulesByID[id] = sarifRule{
				ID:               id,
				Name:             finding.Title,
				ShortDescription: sarifMultiformatMessage{Text: defaultMessage(finding)},
				DefaultConfiguration: &sarifReportingDescriptor{
					Level: severityFailLevel(finding.Severity),
				},
			}
		}

		if finding.Status != eval.StatusFail && finding.Status != eval.StatusInfo {
			continue
		}
		results = append(results, sarifResult{
			RuleID: id,
			Level:  findingLevel(finding),
			Message: sarifMultiformatMessage{
				Text: defaultMessage(finding),
			},
		})
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rulesOut := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rulesOut = append(rulesOut, rulesByID[id])
	}

	out := sarifRoot{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "STANCE",
						Version: strings.TrimSpace(doc.Tool.Version),
						Rules:   rulesOut,
					},
				},
				Results: results,
			},
		},
	}

	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func findingLevel(f eval.Finding) string {
	if f.Status == eval.StatusInfo {
		return "note"
	}
	return severityFailLevel(f.Severity)
}

func severityFailLevel(sev rules.Severity) string {
	switch sev {
	case rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow:
		return "warning"
	default:
		return "warning"
	}
}

func defaultMessage(f eval.Finding) string {
	if strings.TrimSpace(f.Summary) != "" {
		return f.Summary
	}
	if strings.TrimSpace(f.Title) != "" {
		return f.Title
	}
	return f.RuleID
}
