package eval

import (
	"encoding/json"
	"testing"

	"github.com/goldjg/stance/internal/core/rules"
)

func TestFindingJSONOmitsDetailsWhenEmpty(t *testing.T) {
	f := Finding{
		RuleID:   "TEST-001",
		Title:    "Test finding",
		Severity: rules.SeverityLow,
		Status:   StatusInfo,
		Summary:  "Informational summary",
	}

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal finding json: %v", err)
	}
	if _, ok := parsed["details"]; ok {
		t.Fatalf("details should be omitted when empty, got %#v", parsed["details"])
	}
}

func TestFindingJSONIncludesDetailsWhenPresent(t *testing.T) {
	f := Finding{
		RuleID:   "TEST-001",
		Title:    "Test finding",
		Severity: rules.SeverityLow,
		Status:   StatusInfo,
		Summary:  "Informational summary",
		Details: map[string]any{
			"sample": map[string]any{
				"value": "present",
			},
		},
	}

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal finding json: %v", err)
	}
	details, ok := parsed["details"].(map[string]any)
	if !ok {
		t.Fatalf("expected details object, got %#v", parsed["details"])
	}
	sample, ok := details["sample"].(map[string]any)
	if !ok || sample["value"] != "present" {
		t.Fatalf("unexpected details payload: %#v", parsed["details"])
	}
}
