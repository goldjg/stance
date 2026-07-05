package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/goldjg/stance/internal/core/eval"
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
