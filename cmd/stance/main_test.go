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

func TestRunCheckJSONIncludesPrivilegedCAEvidenceDetails(t *testing.T) {
	tmpDir := t.TempDir()
	factsPath := filepath.Join(tmpDir, "facts.json")
	factsPayload := `{
  "conditional_access_policies":[
    {"id":"policy-1","display_name":"Privileged role MFA","state":"enabled","included_roles":["role-1"],"excluded_users":["principal-1"],"built_in_controls":["mfa"]}
  ],
  "directory_role_assignments":[
    {"id":"assign-1","role_definition_id":"role-1","role_display_name":"Global Administrator","principal_id":"principal-1","principal_display_name":"Alice","source":"graph:/v1.0/roleManagement/directory/roleAssignments"},
    {"id":"assign-2","role_definition_id":"role-2","role_display_name":"Privileged Role Administrator","principal_id":"principal-2","principal_display_name":"Bob","source":"graph:/v1.0/roleManagement/directory/roleAssignments"}
  ],
  "privileged_principals":[
    {"principal_id":"principal-1","principal_type":"user","display_name":"Alice","user_principal_name":"alice@example.com","role_definition_ids":["role-1"],"role_display_names":["Global Administrator"]},
    {"principal_id":"principal-2","principal_type":"user","display_name":"Bob","user_principal_name":"bob@example.com","role_definition_ids":["role-2"],"role_display_names":["Privileged Role Administrator"]}
  ]
}`
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

	findings, ok := parsed["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %#v", parsed["findings"])
	}
	targets := map[string]struct{}{
		"ENTRA-CA-006": {},
		"ENTRA-CA-007": {},
		"ENTRA-CA-008": {},
	}
	found := 0
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ruleID, _ := finding["rule_id"].(string)
		if _, wanted := targets[ruleID]; !wanted {
			continue
		}
		found++
		details, ok := finding["details"].(map[string]any)
		if !ok {
			t.Fatalf("expected details object on %s, got %#v", ruleID, finding["details"])
		}
		evidence, ok := details["privileged_ca_evidence"].(map[string]any)
		if !ok {
			t.Fatalf("expected privileged_ca_evidence on %s, got %#v", ruleID, details["privileged_ca_evidence"])
		}
		if _, ok := evidence["summary"].(map[string]any); !ok {
			t.Fatalf("expected summary object on %s, got %#v", ruleID, evidence["summary"])
		}
		if _, ok := evidence["principals"].([]any); !ok {
			t.Fatalf("expected principals array on %s, got %#v", ruleID, evidence["principals"])
		}
	}
	if found != 3 {
		t.Fatalf("expected details for 3 privileged CA findings, found %d", found)
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

func TestRunCheckWithRoleFactsKeepsReportOutputsWorking(t *testing.T) {
	tmpDir := t.TempDir()
	factsPath := filepath.Join(tmpDir, "facts.json")
	factsPayload := `{
  "directory_role_definitions":[{"id":"role-1","display_name":"Global Administrator"}],
  "directory_role_assignments":[{"id":"assign-1","role_definition_id":"role-1","role_display_name":"Global Administrator","principal_id":"principal-1","principal_display_name":"Alice","source":"graph:/v1.0/roleManagement/directory/roleAssignments"}],
  "privileged_principals":[{"principal_id":"principal-1","display_name":"Alice","role_definition_ids":["role-1"],"role_display_names":["Global Administrator"]}]
}`
	if err := os.WriteFile(factsPath, []byte(factsPayload), 0o600); err != nil {
		t.Fatalf("write facts: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer

	code := run([]string{"check", "--facts", factsPath, "--format", "sarif"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}
	if !strings.Contains(out.String(), `"ruleId": "ENTRA-ROLE-001"`) || !strings.Contains(out.String(), `"ruleId": "ENTRA-ROLE-002"`) {
		t.Fatalf("expected role findings in sarif output: %q", out.String())
	}
	if strings.Contains(out.String(), `"locations"`) {
		t.Fatalf("sarif output should not include synthetic locations: %q", out.String())
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

func TestRunReportJSONPreservesDetails(t *testing.T) {
	tmpDir := t.TempDir()
	resultsPath := filepath.Join(tmpDir, "results.json")
	resultsPayload := `{
  "schema_version": "stance.result.v1",
  "generated_at_utc": "2026-07-05T18:16:07Z",
  "tool": {"name": "stance", "version": "dev", "commit": "none", "date": "unknown"},
  "provider": "microsoft365",
  "suite": "entra",
  "findings": [
    {
      "rule_id":"ENTRA-CA-006",
      "title":"Privileged principal Conditional Access coverage evidence is observed",
      "severity":"low",
      "status":"info",
      "summary":"Observed enforcing Conditional Access coverage evidence.",
      "details":{
        "privileged_ca_evidence":{
          "summary":{
            "total_privileged_principals":2,
            "principals_with_coverage_evidence":1,
            "principals_with_direct_exclusion_evidence":1,
            "principals_with_possible_exclusion_evidence":0,
            "principals_with_unknown_coverage":1
          },
          "principals":[
            {"principal_id":"principal-1","coverage_evidence":["Observed enabled policy"],"limitations":["Group membership expansion is not implemented in this release."]},
            {"principal_id":"principal-2","coverage_evidence":[],"limitations":["Group membership expansion is not implemented in this release."]}
          ]
        }
      }
    }
  ]
}`
	if err := os.WriteFile(resultsPath, []byte(resultsPayload), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}

	var out bytes.Buffer
	var err bytes.Buffer
	code := run([]string{"report", "--results", resultsPath, "--format", "json"}, &out, &err)
	if code != 0 {
		t.Fatalf("expected success; code=%d stderr=%q", code, err.String())
	}

	var parsed map[string]any
	if decodeErr := json.Unmarshal(out.Bytes(), &parsed); decodeErr != nil {
		t.Fatalf("expected json output, decode error: %v; output=%q", decodeErr, out.String())
	}
	findings, ok := parsed["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected one finding in output, got %#v", parsed["findings"])
	}
	finding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected finding object, got %#v", findings[0])
	}
	details, ok := finding["details"].(map[string]any)
	if !ok {
		t.Fatalf("expected details object, got %#v", finding["details"])
	}
	evidence, ok := details["privileged_ca_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("expected privileged_ca_evidence object, got %#v", details["privileged_ca_evidence"])
	}
	summary, ok := evidence["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", evidence["summary"])
	}
	if summary["total_privileged_principals"] != float64(2) {
		t.Fatalf("unexpected summary content after report conversion: %#v", summary)
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
	if !strings.Contains(out.String(), "RoleManagement.Read.Directory") {
		t.Fatalf("expected role-management permission in output: %q", out.String())
	}
	if !strings.Contains(out.String(), "Directory.Read.All may be required for principal detail resolution") {
		t.Fatalf("expected principal-detail guidance note in output: %q", out.String())
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
	if !strings.Contains(out.String(), "RoleManagement.Read.Directory") {
		t.Fatalf("expected role-management permission in output: %q", out.String())
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
	if !strings.Contains(out.String(), "ENTRA-ROLE-001") {
		t.Fatalf("expected role checks output: %q", out.String())
	}
	if !strings.Contains(out.String(), "ENTRA-CA-006") || !strings.Contains(out.String(), "ENTRA-CA-008") {
		t.Fatalf("expected privileged CA evidence checks output: %q", out.String())
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
