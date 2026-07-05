package catalog

import (
	"testing"

	corecatalog "github.com/goldjg/stance/internal/core/catalog"
)

func TestProvider(t *testing.T) {
	provider := Provider()
	if provider.Name != ProviderName {
		t.Fatalf("unexpected provider name: %s", provider.Name)
	}
	if len(provider.Suites) == 0 {
		t.Fatalf("expected suites for provider")
	}
}

func TestSuitesIncludesEntra(t *testing.T) {
	suites := Suites()
	if len(suites) != 1 {
		t.Fatalf("expected one suite, got %d", len(suites))
	}
	suite := suites[0]
	if suite.ID != "entra" {
		t.Fatalf("expected entra suite, got %s", suite.ID)
	}
	if suite.CheckCount != 11 {
		t.Fatalf("expected 11 checks in entra suite, got %d", suite.CheckCount)
	}
}

func TestChecksFromRuleMetadata(t *testing.T) {
	checks := Checks()
	if len(checks) != 11 {
		t.Fatalf("expected 11 checks, got %d", len(checks))
	}

	first := checks[0]
	if first.ID != "ENTRA-CA-001" {
		t.Fatalf("unexpected first check id: %s", first.ID)
	}
	if first.Provider != ProviderName {
		t.Fatalf("unexpected provider for check: %s", first.Provider)
	}
	if len(first.RequiredPermissions) == 0 || first.RequiredPermissions[0] != "Policy.Read.All" {
		t.Fatalf("unexpected required permissions: %#v", first.RequiredPermissions)
	}
	if _, ok := findCheckByID(checks, "ENTRA-CA-006"); !ok {
		t.Fatalf("expected ENTRA-CA-006 in catalog")
	}
	if _, ok := findCheckByID(checks, "ENTRA-CA-007"); !ok {
		t.Fatalf("expected ENTRA-CA-007 in catalog")
	}
	if _, ok := findCheckByID(checks, "ENTRA-CA-008"); !ok {
		t.Fatalf("expected ENTRA-CA-008 in catalog")
	}
	collect, ok := findCheckByID(checks, "ENTRA-COLLECT-001")
	if !ok {
		t.Fatalf("expected ENTRA-COLLECT-001 in catalog")
	}
	if !containsString(collect.DataRequirements, "organization") {
		t.Fatalf("expected organization data requirement on ENTRA-COLLECT-001, got %#v", collect.DataRequirements)
	}
	if !containsString(collect.DataRequirements, "principal_group_resolutions") {
		t.Fatalf("expected principal_group_resolutions data requirement on ENTRA-COLLECT-001, got %#v", collect.DataRequirements)
	}
	coverage, ok := findCheckByID(checks, "ENTRA-CA-006")
	if !ok {
		t.Fatalf("expected ENTRA-CA-006 in catalog")
	}
	if !containsString(coverage.DataRequirements, "principal_group_memberships") {
		t.Fatalf("expected principal_group_memberships data requirement on ENTRA-CA-006, got %#v", coverage.DataRequirements)
	}
	if !containsString(coverage.DataRequirements, "principal_group_resolutions") {
		t.Fatalf("expected principal_group_resolutions data requirement on ENTRA-CA-006, got %#v", coverage.DataRequirements)
	}
	exclusions, ok := findCheckByID(checks, "ENTRA-CA-007")
	if !ok {
		t.Fatalf("expected ENTRA-CA-007 in catalog")
	}
	if !containsString(exclusions.DataRequirements, "principal_group_resolutions") {
		t.Fatalf("expected principal_group_resolutions data requirement on ENTRA-CA-007, got %#v", exclusions.DataRequirements)
	}
	unknown, ok := findCheckByID(checks, "ENTRA-CA-008")
	if !ok {
		t.Fatalf("expected ENTRA-CA-008 in catalog")
	}
	if !containsString(unknown.DataRequirements, "principal_group_resolutions") {
		t.Fatalf("expected principal_group_resolutions data requirement on ENTRA-CA-008, got %#v", unknown.DataRequirements)
	}
}

func findCheckByID(checks []corecatalog.CheckInfo, id string) (corecatalog.CheckInfo, bool) {
	for _, check := range checks {
		if check.ID == id {
			return check, true
		}
	}
	return corecatalog.CheckInfo{}, false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
