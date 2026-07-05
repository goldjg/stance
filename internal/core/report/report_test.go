package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goldjg/stance/internal/core/eval"
	"github.com/goldjg/stance/internal/core/result"
	"github.com/goldjg/stance/internal/core/rules"
)

func sampleDocument() result.Document {
	return result.Document{
		SchemaVersion:  result.SchemaVersionV1,
		GeneratedAtUTC: "2026-07-05T18:16:07Z",
		Tool: result.ToolMetadata{
			Name:    "stance",
			Version: "dev",
			Commit:  "none",
			Date:    "unknown",
		},
		Provider: "microsoft365",
		Suite:    "entra",
		Findings: []eval.Finding{
			{
				RuleID:       "TEST-001",
				Title:        "First generic posture finding",
				Severity:     rules.SeverityMedium,
				Status:       eval.StatusFail,
				Summary:      "Detected failing condition.",
				MatchedItems: []string{"Matched item A"},
			},
			{
				RuleID:   "TEST-002",
				Title:    "Second generic posture finding",
				Severity: rules.SeverityLow,
				Status:   eval.StatusPass,
				Summary:  "No failing conditions detected.",
			},
		},
	}
}

func TestJSONGolden(t *testing.T) {
	got, err := JSON(sampleDocument())
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
	got := Markdown(sampleDocument())
	want, err := os.ReadFile(filepath.Join("testdata", "report.md.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("markdown report mismatch\n--- got ---\n%s\n--- want ---\n%s", string(got), string(want))
	}
}

func TestSARIFGolden(t *testing.T) {
	got, err := SARIF(sampleDocument())
	if err != nil {
		t.Fatalf("SARIF returned error: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "report.sarif.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("sarif report mismatch\n--- got ---\n%s\n--- want ---\n%s", string(got), string(want))
	}
}

func TestJUnitOutput(t *testing.T) {
	got, err := JUnit(sampleDocument())
	if err != nil {
		t.Fatalf("JUnit returned error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "<testsuite") || !strings.Contains(s, `failures="1"`) {
		t.Fatalf("unexpected junit output: %s", s)
	}
	if !strings.Contains(s, `timestamp="2026-07-05T18:16:07Z"`) {
		t.Fatalf("unexpected junit timestamp: %s", s)
	}
}

func TestHTMLEscaped(t *testing.T) {
	doc := sampleDocument()
	doc.Findings = []eval.Finding{
		{
			RuleID:       "TEST-999",
			Title:        `Unsafe <script>alert("x")</script> title`,
			Severity:     rules.SeverityLow,
			Status:       eval.StatusInfo,
			Summary:      "Observed informational evidence.",
			MatchedItems: []string{`Role <admin>`, `User "breakglass"`},
		},
	}

	got, err := HTML(doc)
	if err != nil {
		t.Fatalf("HTML returned error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "STANCE check report") {
		t.Fatalf("missing report title: %s", s)
	}
	if !strings.Contains(s, "2026-07-05T18:16:07Z") {
		t.Fatalf("missing generated timestamp: %s", s)
	}
	if !strings.Contains(s, "Informational finding: this is evidence-only context") {
		t.Fatalf("missing informational caution note: %s", s)
	}
	if strings.Contains(s, `<script>alert("x")</script>`) {
		t.Fatalf("expected html escaping, got raw script tag: %s", s)
	}
	if !strings.Contains(s, "Unsafe &lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; title") {
		t.Fatalf("missing escaped title: %s", s)
	}
	if !strings.Contains(s, "Role &lt;admin&gt;") {
		t.Fatalf("missing escaped matched item: %s", s)
	}
	if !strings.Contains(s, "<td>total</td><td>1</td>") {
		t.Fatalf("missing total status summary: %s", s)
	}
}

func TestSARIFOutput(t *testing.T) {
	doc := sampleDocument()
	doc.Findings = []eval.Finding{
		{
			RuleID:   "TEST-HIGH",
			Title:    "High severity fail",
			Severity: rules.SeverityHigh,
			Status:   eval.StatusFail,
			Summary:  "High issue detected",
		},
		{
			RuleID:   "TEST-INFO",
			Title:    "Informational note",
			Severity: rules.SeverityLow,
			Status:   eval.StatusInfo,
			Summary:  "Evidence observed",
		},
		{
			RuleID:   "TEST-PASS",
			Title:    "Passing check",
			Severity: rules.SeverityLow,
			Status:   eval.StatusPass,
			Summary:  "No issue",
		},
	}

	got, err := SARIF(doc)
	if err != nil {
		t.Fatalf("SARIF returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("sarif should be valid json: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Fatalf("unexpected sarif version: %#v", parsed["version"])
	}

	s := string(got)
	if !strings.Contains(s, `"name": "STANCE"`) {
		t.Fatalf("missing stance tool name: %s", s)
	}
	if !strings.Contains(s, `"ruleId": "TEST-HIGH"`) || !strings.Contains(s, `"ruleId": "TEST-INFO"`) {
		t.Fatalf("missing expected sarif results: %s", s)
	}
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("expected sarif runs: %#v", parsed["runs"])
	}
	run0, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected sarif run object: %#v", runs[0])
	}
	results, ok := run0["results"].([]any)
	if !ok {
		t.Fatalf("expected sarif results array: %#v", run0["results"])
	}
	for _, entry := range results {
		resultEntry, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if resultEntry["ruleId"] == "TEST-PASS" {
			t.Fatalf("pass findings should not emit sarif results: %s", s)
		}
	}
	if strings.Contains(s, `"locations"`) {
		t.Fatalf("sarif should not invent source locations: %s", s)
	}
}

func TestRenderersHandleFindingDetails(t *testing.T) {
	doc := sampleDocument()
	doc.Findings[0].Details = map[string]any{
		"privileged_ca_evidence": map[string]any{
			"summary": map[string]any{
				"total_privileged_principals": 2,
			},
			"principals": []map[string]any{
				{"principal_id": "principal-1"},
				{"principal_id": "principal-2"},
			},
		},
	}

	if _, err := JSON(doc); err != nil {
		t.Fatalf("JSON should support findings with details: %v", err)
	}
	if got := Markdown(doc); len(got) == 0 {
		t.Fatalf("markdown output should not be empty")
	}
	if _, err := HTML(doc); err != nil {
		t.Fatalf("HTML should support findings with details: %v", err)
	}
	junit, err := JUnit(doc)
	if err != nil {
		t.Fatalf("JUnit should support findings with details: %v", err)
	}
	if strings.Contains(string(junit), "privileged_ca_evidence") {
		t.Fatalf("JUnit output should remain compact and not include structured details: %s", string(junit))
	}
	sarif, err := SARIF(doc)
	if err != nil {
		t.Fatalf("SARIF should support findings with details: %v", err)
	}
	if strings.Contains(string(sarif), `"locations"`) {
		t.Fatalf("sarif should not invent source locations: %s", string(sarif))
	}
}
