package result

import (
	"testing"
	"time"

	"github.com/goldjg/stance/internal/core/eval"
)

func TestNewDocumentDefaults(t *testing.T) {
	doc := NewDocument("microsoft365", "entra", []eval.Finding{}, ToolMetadata{Name: "stance"}, time.Time{})
	if doc.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("unexpected schema version: %q", doc.SchemaVersion)
	}
	if doc.GeneratedAtUTC == "" {
		t.Fatalf("expected generated timestamp")
	}
	if err := (&doc).Validate(); err != nil {
		t.Fatalf("expected valid doc: %v", err)
	}
}

func TestParseJSONRejectsUnsupportedSchema(t *testing.T) {
	_, err := ParseJSON([]byte(`{
  "schema_version":"stance.result.v0",
  "generated_at_utc":"2026-07-05T18:16:07Z",
  "tool":{"name":"stance","version":"dev","commit":"none","date":"unknown"},
  "provider":"microsoft365",
  "findings":[]
}`))
	if err == nil {
		t.Fatalf("expected parse failure for unsupported schema")
	}
}

func TestParseJSONAcceptsOptionalFindingDetailsInV1(t *testing.T) {
	doc, err := ParseJSON([]byte(`{
  "schema_version":"stance.result.v1",
  "generated_at_utc":"2026-07-05T18:16:07Z",
  "tool":{"name":"stance","version":"dev","commit":"none","date":"unknown"},
  "provider":"microsoft365",
  "findings":[
    {
      "rule_id":"ENTRA-CA-006",
      "title":"Privileged principal Conditional Access coverage evidence is observed",
      "severity":"low",
      "status":"info",
      "summary":"Evidence summary.",
      "details":{"privileged_ca_evidence":{"summary":{"total_privileged_principals":1},"principals":[]}}
    }
  ]
}`))
	if err != nil {
		t.Fatalf("expected details to be additive-compatible in v1: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(doc.Findings))
	}
	if _, ok := doc.Findings[0].Details["privileged_ca_evidence"].(map[string]any); !ok {
		t.Fatalf("expected parsed details payload, got %#v", doc.Findings[0].Details)
	}
}
