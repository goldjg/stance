package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goldjg/stance/internal/core/eval"
	"github.com/goldjg/stance/internal/core/rules"
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

func TestHTMLStableAndEscaped(t *testing.T) {
	originalNow := nowUTC
	nowUTC = func() time.Time {
		return time.Date(2026, time.July, 5, 18, 16, 7, 0, time.UTC)
	}
	defer func() {
		nowUTC = originalNow
	}()

	result := eval.Result{
		Findings: []eval.Finding{
			{
				RuleID:       "ENTRA-CA-999",
				Title:        `Unsafe <script>alert("x")</script> title`,
				Severity:     rules.SeverityLow,
				Status:       eval.StatusInfo,
				Summary:      "Observed informational evidence.",
				MatchedItems: []string{`Role <admin>`, `User "breakglass"`},
			},
		},
	}

	got, err := HTML(result)
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
