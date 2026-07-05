package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/goldjg/stance/internal/core/eval"
	"github.com/goldjg/stance/internal/core/rules"
)

func JSON(result eval.Result) ([]byte, error) {
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func Markdown(result eval.Result) []byte {
	var b bytes.Buffer
	b.WriteString("# STANCE check summary\n\n")
	b.WriteString("| Rule ID | Severity | Status | Summary |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, f := range result.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.RuleID, f.Severity, f.Status, f.Summary)
	}
	return b.Bytes()
}

func JUnit(result eval.Result) ([]byte, error) {
	type failure struct {
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		Failure   *failure `xml:"failure,omitempty"`
	}
	type testsuite struct {
		XMLName   xml.Name   `xml:"testsuite"`
		Name      string     `xml:"name,attr"`
		Tests     int        `xml:"tests,attr"`
		Failures  int        `xml:"failures,attr"`
		Timestamp string     `xml:"timestamp,attr"`
		TestCases []testcase `xml:"testcase"`
	}

	cases := make([]testcase, 0, len(result.Findings))
	failures := 0
	for _, finding := range result.Findings {
		tc := testcase{
			Name:      finding.RuleID,
			Classname: "STANCE",
		}
		if finding.Status == eval.StatusFail {
			failures++
			tc.Failure = &failure{
				Message: finding.Title,
				Text:    finding.Summary,
			}
		}
		cases = append(cases, tc)
	}

	suite := testsuite{
		Name:      "STANCE Checks",
		Tests:     len(cases),
		Failures:  failures,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TestCases: cases,
	}
	out, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(out, '\n')...), nil
}

var nowUTC = func() time.Time {
	return time.Now().UTC()
}

type Summary struct {
	Total            int                    `json:"total"`
	PassCount        int                    `json:"pass_count"`
	FailCount        int                    `json:"fail_count"`
	InfoCount        int                    `json:"info_count"`
	CountsBySeverity map[rules.Severity]int `json:"counts_by_severity"`
}

func Summarize(result eval.Result) Summary {
	summary := Summary{
		Total:            len(result.Findings),
		CountsBySeverity: make(map[rules.Severity]int),
	}
	for _, finding := range result.Findings {
		switch finding.Status {
		case eval.StatusPass:
			summary.PassCount++
		case eval.StatusFail:
			summary.FailCount++
		case eval.StatusInfo:
			summary.InfoCount++
		}
		summary.CountsBySeverity[finding.Severity]++
	}
	return summary
}

func HTML(result eval.Result) ([]byte, error) {
	type statusCount struct {
		Label string
		Count int
	}
	type severityCount struct {
		Label string
		Count int
	}
	type findingView struct {
		RuleID            string
		Title             string
		Severity          string
		Status            string
		Summary           string
		MatchedItems      []string
		InformationalNote string
	}
	type templateData struct {
		Title          string
		GeneratedAtUTC string
		StatusCounts   []statusCount
		SeverityCounts []severityCount
		Findings       []findingView
	}

	summary := Summarize(result)
	findings := make([]findingView, 0, len(result.Findings))
	for _, finding := range result.Findings {
		note := ""
		if finding.Status == eval.StatusInfo {
			note = "Informational finding: this is evidence-only context and does not by itself prove a misconfiguration."
		}
		findings = append(findings, findingView{
			RuleID:            finding.RuleID,
			Title:             finding.Title,
			Severity:          string(finding.Severity),
			Status:            string(finding.Status),
			Summary:           finding.Summary,
			MatchedItems:      append([]string(nil), finding.MatchedItems...),
			InformationalNote: note,
		})
	}

	severityOrder := []rules.Severity{rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow}
	severityCounts := make([]severityCount, 0, len(severityOrder))
	for _, sev := range severityOrder {
		severityCounts = append(severityCounts, severityCount{
			Label: string(sev),
			Count: summary.CountsBySeverity[sev],
		})
	}

	data := templateData{
		Title:          "STANCE check report",
		GeneratedAtUTC: nowUTC().Format(time.RFC3339),
		StatusCounts: []statusCount{
			{Label: string(eval.StatusPass), Count: summary.PassCount},
			{Label: string(eval.StatusFail), Count: summary.FailCount},
			{Label: string(eval.StatusInfo), Count: summary.InfoCount},
			{Label: "total", Count: summary.Total},
		},
		SeverityCounts: severityCounts,
		Findings:       findings,
	}

	const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{.Title}}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    h1, h2 { margin-bottom: 8px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 18px; }
    th, td { border: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f6f8fa; }
    ul { margin: 0; padding-left: 20px; }
    p.meta { color: #57606a; margin-top: 0; }
    em { color: #57606a; }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>
  <p class="meta">Generated: {{.GeneratedAtUTC}}</p>

  <h2>Summary by status</h2>
  <table>
    <thead><tr><th>Status</th><th>Count</th></tr></thead>
    <tbody>
    {{range .StatusCounts}}
      <tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
    {{end}}
    </tbody>
  </table>

  <h2>Summary by severity</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
    {{range .SeverityCounts}}
      <tr><td>{{.Label}}</td><td>{{.Count}}</td></tr>
    {{end}}
    </tbody>
  </table>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>Title</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Summary</th>
        <th>Matched items</th>
      </tr>
    </thead>
    <tbody>
    {{range .Findings}}
      <tr>
        <td>{{.RuleID}}</td>
        <td>{{.Title}}</td>
        <td>{{.Severity}}</td>
        <td>{{.Status}}</td>
        <td>{{.Summary}}{{if .InformationalNote}}<br><em>{{.InformationalNote}}</em>{{end}}</td>
        <td>{{if .MatchedItems}}<ul>{{range .MatchedItems}}<li>{{.}}</li>{{end}}</ul>{{else}}&mdash;{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</body>
</html>
`

	tpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if err := tpl.Execute(&b, data); err != nil {
		return nil, err
	}

	out := b.Bytes()
	if !strings.HasSuffix(string(out), "\n") {
		out = append(out, '\n')
	}
	return out, nil
}
