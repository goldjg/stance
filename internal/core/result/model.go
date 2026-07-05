package result

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/goldjg/stance/internal/core/eval"
)

const SchemaVersionV1 = "stance.result.v1"

type ToolMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type Document struct {
	SchemaVersion  string         `json:"schema_version"`
	GeneratedAtUTC string         `json:"generated_at_utc"`
	Tool           ToolMetadata   `json:"tool"`
	Provider       string         `json:"provider"`
	Suite          string         `json:"suite,omitempty"`
	Findings       []eval.Finding `json:"findings"`
}

func NewDocument(provider, suite string, findings []eval.Finding, tool ToolMetadata, generatedAt time.Time) Document {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	out := Document{
		SchemaVersion:  SchemaVersionV1,
		GeneratedAtUTC: generatedAt.UTC().Format(time.RFC3339),
		Tool:           tool,
		Provider:       provider,
		Suite:          strings.TrimSpace(suite),
		Findings:       append([]eval.Finding(nil), findings...),
	}
	return out
}

func ParseJSON(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, err
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func (d *Document) Validate() error {
	if d == nil {
		return errors.New("result document is nil")
	}
	if strings.TrimSpace(d.SchemaVersion) != SchemaVersionV1 {
		return fmt.Errorf("unsupported schema_version: %q", d.SchemaVersion)
	}
	if strings.TrimSpace(d.GeneratedAtUTC) == "" {
		return errors.New("generated_at_utc is required")
	}
	if _, err := time.Parse(time.RFC3339, d.GeneratedAtUTC); err != nil {
		return fmt.Errorf("generated_at_utc is invalid: %w", err)
	}
	if strings.TrimSpace(d.Tool.Name) == "" {
		return errors.New("tool.name is required")
	}
	if strings.TrimSpace(d.Provider) == "" {
		return errors.New("provider is required")
	}
	if d.Findings == nil {
		d.Findings = []eval.Finding{}
	}
	return nil
}
