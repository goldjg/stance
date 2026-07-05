package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goldjg/stance-365/internal/eval"
	"github.com/goldjg/stance-365/internal/rules"
)

func sampleResult() eval.Result {
	return eval.Result{
		Findings: []eval.Finding{
			{
				RuleID:       "ENTRA-CA-001",
				Title:        "Disabled Conditional Access policies are identified",
				Severity:     rules.SeverityMedium,
				Status:       eval.StatusFail,
				Summary:      "Detected disabled policies.",
				MatchedItems: []string{"Disabled policy"},
			},
			{
				RuleID:   "ENTRA-CA-002",
				Title:    "Report-only Conditional Access policies are identified",
				Severity: rules.SeverityLow,
				Status:   eval.StatusPass,
				Summary:  "No report-only policies detected.",
			},
		},
	}
}

func TestJSONGolden(t *testing.T) {
	got, err := JSON(sampleResult())
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "report.json.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("json report mismatch\n--- got ---\n%s\n--- want ---\n%s", string(got), string(want))
	}
}

func TestMarkdownGolden(t *testing.T) {
	got := Markdown(sampleResult())
	want, err := os.ReadFile(filepath.Join("testdata", "report.md.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("markdown report mismatch\n--- got ---\n%s\n--- want ---\n%s", string(got), string(want))
	}
}

func TestJUnitOutput(t *testing.T) {
	got, err := JUnit(sampleResult())
	if err != nil {
		t.Fatalf("JUnit returned error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "<testsuite") || !strings.Contains(s, `failures="1"`) {
		t.Fatalf("unexpected junit output: %s", s)
	}
}
