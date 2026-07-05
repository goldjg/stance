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
