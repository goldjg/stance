package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"version"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "stance version=") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
	if err.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", err.String())
	}
}

func TestRunInit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "stance.yaml")

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"init", configPath}, &out, &err)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "created") {
		t.Fatalf("unexpected init output: %q", out.String())
	}
}

func TestRunAuthMissingSubcommand(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"auth"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for missing auth subcommand")
	}
	if !strings.Contains(err.String(), "missing subcommand") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunCheckJSON(t *testing.T) {
	tmpDir := t.TempDir()
	factsPath := filepath.Join(tmpDir, "facts.json")
	factsPayload := `{"conditional_access_policies":[{"display_name":"P1","state":"disabled"}]}`
	if err := os.WriteFile(factsPath, []byte(factsPayload), 0o600); err != nil {
		t.Fatalf("write facts: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"check", "--facts", factsPath, "--format", "json"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	var parsed map[string]any
	if decodeErr := json.Unmarshal(out.Bytes(), &parsed); decodeErr != nil {
		t.Fatalf("expected json output, decode error: %v; output=%q", decodeErr, out.String())
	}
	if parsed["schema_version"] != "stance.result.v1" {
		t.Fatalf("expected schema_version stance.result.v1, got %#v", parsed["schema_version"])
	}
	if parsed["provider"] != "microsoft365" {
		t.Fatalf("expected provider microsoft365, got %#v", parsed["provider"])
	}
	tool, ok := parsed["tool"].(map[string]any)
	if !ok || tool["name"] != "stance" {
		t.Fatalf("expected tool metadata with name=stance, got %#v", parsed["tool"])
	}
	if _, ok := parsed["findings"].([]any); !ok {
		t.Fatalf("expected findings array in result document, got %#v", parsed["findings"])
	}
}

func TestRunCheckHTML(t *testing.T) {
	tmpDir := t.TempDir()
	factsPath := filepath.Join(tmpDir, "facts.json")
	factsPayload := `{"conditional_access_policies":[{"display_name":"P1","state":"disabled"}]}`
	if err := os.WriteFile(factsPath, []byte(factsPayload), 0o600); err != nil {
		t.Fatalf("write facts: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"check", "--facts", factsPath, "--format", "html"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "<!doctype html>") || !strings.Contains(out.String(), "STANCE check report") {
		t.Fatalf("unexpected html output: %q", out.String())
	}
}

func TestRunCheckSARIF(t *testing.T) {
	tmpDir := t.TempDir()
	factsPath := filepath.Join(tmpDir, "facts.json")
	factsPayload := `{"conditional_access_policies":[{"display_name":"P1","state":"disabled"}]}`
	if err := os.WriteFile(factsPath, []byte(factsPayload), 0o600); err != nil {
		t.Fatalf("write facts: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"check", "--facts", factsPath, "--format", "sarif"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || !strings.Contains(out.String(), `"name": "STANCE"`) {
		t.Fatalf("unexpected sarif output: %q", out.String())
	}
}

func TestRunReportRequiresResults(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"report", "--format", "html"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure without --results")
	}
	if !strings.Contains(err.String(), "report requires --results") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunReportMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	if err := os.WriteFile(resultsPath, []byte("{bad-json"), 0o600); err != nil {
		t.Fatalf("write malformed results: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"report", "--results", resultsPath, "--format", "html"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure for malformed result json")
	}
	if !strings.Contains(err.String(), "report failed to parse results") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunReportUnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	resultsPayload := `{
  "schema_version": "stance.result.v1",
  "generated_at_utc": "2026-07-05T18:16:07Z",
  "tool": {"name": "stance", "version": "dev", "commit": "none", "date": "unknown"},
  "provider": "microsoft365",
  "suite": "entra",
  "findings": []
}`
	if err := os.WriteFile(resultsPath, []byte(resultsPayload), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"report", "--results", resultsPath, "--format", "csv"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected unsupported format failure")
	}
	if !strings.Contains(err.String(), "unsupported format: csv") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunReportOfflineSARIF(t *testing.T) {
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	resultsPayload := `{
  "schema_version": "stance.result.v1",
  "generated_at_utc": "2026-07-05T18:16:07Z",
  "tool": {"name": "stance", "version": "dev", "commit": "none", "date": "unknown"},
  "provider": "microsoft365",
  "suite": "entra",
  "findings": [
    {"rule_id":"ENTRA-CA-001","title":"Disabled CA policies","severity":"medium","status":"fail","summary":"Detected disabled policies."},
    {"rule_id":"ENTRA-CA-005","title":"User exclusions observed","severity":"low","status":"info","summary":"Observed exclusions."}
  ]
}`
	if err := os.WriteFile(resultsPath, []byte(resultsPayload), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
	t.Setenv("STANCE_CLIENT_SECRET", "not-needed")
	t.Setenv("STANCE_CLIENT_ASSERTION", "not-needed")
	t.Setenv("STANCE_FEDERATED_TOKEN_FILE", "/nonexistent")

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"report", "--results", resultsPath, "--format", "sarif"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || !strings.Contains(out.String(), `"ruleId": "ENTRA-CA-001"`) {
		t.Fatalf("unexpected sarif output: %q", out.String())
	}
	if strings.Contains(out.String(), `"locations"`) {
		t.Fatalf("sarif output should not include synthetic locations: %q", out.String())
	}
}

func TestRunReportWritesOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	outPath := filepath.Join(tmpDir, "report.md")
	resultsPayload := `{
  "schema_version": "stance.result.v1",
  "generated_at_utc": "2026-07-05T18:16:07Z",
  "tool": {"name": "stance", "version": "dev", "commit": "none", "date": "unknown"},
  "provider": "microsoft365",
  "suite": "entra",
  "findings": []
}`
	if err := os.WriteFile(resultsPath, []byte(resultsPayload), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer
	code := run([]string{"report", "--results", resultsPath, "--format", "markdown", "--out", outPath}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}

	info, statErr := os.Stat(outPath)
	if statErr != nil {
		t.Fatalf("expected output file: %v", statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 mode, got %o", info.Mode().Perm())
	}
}

func TestRunPermissionsSuite(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"permissions", "--suite", "entra"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "Policy.Read.All") {
		t.Fatalf("unexpected permissions output: %q", out.String())
	}
}

func TestRunPermissionsSuiteWithProvider(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"permissions", "--provider", "microsoft365", "--suite", "entra"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "Policy.Read.All") {
		t.Fatalf("unexpected permissions output: %q", out.String())
	}
}

func TestRunPermissionsUnsupportedProvider(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"permissions", "--provider", "m365", "--suite", "entra"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure for unsupported provider")
	}
	if !strings.Contains(err.String(), "unsupported provider") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunExplainCheck(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"explain", "--check", "ENTRA-CA-001"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), `"id": "ENTRA-CA-001"`) {
		t.Fatalf("unexpected explain output: %q", out.String())
	}
}

func TestRunProviders(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"providers"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "microsoft365") {
		t.Fatalf("unexpected providers output: %q", out.String())
	}
}

func TestRunSuitesDefaultProvider(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"suites"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "entra") {
		t.Fatalf("unexpected suites output: %q", out.String())
	}
}

func TestRunSuitesUnsupportedProvider(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"suites", "--provider", "m365"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure for unsupported provider")
	}
	if !strings.Contains(err.String(), "unsupported provider") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunChecksDefaultText(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"checks"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "ENTRA-CA-001") {
		t.Fatalf("unexpected checks output: %q", out.String())
	}
}

func TestRunChecksSuiteFilter(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"checks", "--suite", "entra"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), "\tentra\t") {
		t.Fatalf("expected only entra suite checks, got %q", out.String())
	}
}

func TestRunChecksJSON(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"checks", "--provider", "microsoft365", "--suite", "entra", "--format", "json"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}

	var parsed []map[string]any
	if decodeErr := json.Unmarshal(out.Bytes(), &parsed); decodeErr != nil {
		t.Fatalf("expected json output, decode error: %v; output=%q", decodeErr, out.String())
	}
	if len(parsed) == 0 {
		t.Fatalf("expected checks in json output")
	}
	if parsed[0]["provider"] != "microsoft365" {
		t.Fatalf("unexpected provider in json output: %#v", parsed[0]["provider"])
	}
}

func TestRunChecksUnsupportedProvider(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"checks", "--provider", "m365"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure for unsupported provider")
	}
	if !strings.Contains(err.String(), "unsupported provider") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}

func TestRunChecksUnknownSuite(t *testing.T) {
	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"checks", "--suite", "unknown-suite"}, &out, &err)
	if code == 0 {
		t.Fatalf("expected failure for unknown suite")
	}
	if !strings.Contains(err.String(), "unknown suite: unknown-suite") {
		t.Fatalf("unexpected stderr: %q", err.String())
	}
}
