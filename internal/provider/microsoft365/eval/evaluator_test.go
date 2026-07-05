package eval

import (
	"strings"
	"testing"

	coreeval "github.com/goldjg/stance/internal/core/eval"
	corerules "github.com/goldjg/stance/internal/core/rules"
	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

func TestEvaluateDefault(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{DisplayName: "Disabled policy", State: "disabled", IncludedRoles: []string{"role-1"}, BuiltInControls: []string{"mfa"}, ExcludedUsers: []string{"breakglass"}},
			{DisplayName: "Report only policy", State: "enabledForReportingButNotEnforced", IncludedRoles: []string{"role-2"}, AuthenticationStrength: "High assurance"},
		},
	}

	result := EvaluateDefault(bundle)
	if len(result.Findings) != 10 {
		t.Fatalf("expected 10 findings, got %d", len(result.Findings))
	}
	if findingByRuleID(result, "ENTRA-CA-001").Status != coreeval.StatusFail {
		t.Fatalf("expected ENTRA-CA-001 to fail")
	}
	if findingByRuleID(result, "ENTRA-CA-002").Status != coreeval.StatusFail {
		t.Fatalf("expected ENTRA-CA-002 to fail")
	}
	if findingByRuleID(result, "ENTRA-CA-003").Status != coreeval.StatusInfo {
		t.Fatalf("expected ENTRA-CA-003 to be info")
	}
	if findingByRuleID(result, "ENTRA-CA-004").Status != coreeval.StatusPass {
		t.Fatalf("expected ENTRA-CA-004 to pass")
	}
	exclusions := findingByRuleID(result, "ENTRA-CA-005")
	if exclusions.Status != coreeval.StatusInfo {
		t.Fatalf("expected ENTRA-CA-005 to be info")
	}
	if exclusions.Severity != corerules.SeverityLow {
		t.Fatalf("expected exclusions finding severity low, got %s", exclusions.Severity)
	}
	if exclusions.Summary == "" || !strings.Contains(exclusions.Summary, "not proof") {
		t.Fatalf("expected cautious exclusion summary, got %q", exclusions.Summary)
	}
	if findingByRuleID(result, "ENTRA-CA-006").Status != coreeval.StatusInfo {
		t.Fatalf("expected ENTRA-CA-006 to be info")
	}
	if findingByRuleID(result, "ENTRA-CA-007").Status != coreeval.StatusInfo {
		t.Fatalf("expected ENTRA-CA-007 to be info")
	}
	if unknown := findingByRuleID(result, "ENTRA-CA-008"); unknown.Status != coreeval.StatusInfo || !strings.Contains(unknown.Summary, "unknown") {
		t.Fatalf("expected ENTRA-CA-008 to be cautious info, got %+v", unknown)
	}
	if roleVisibility := findingByRuleID(result, "ENTRA-ROLE-001"); roleVisibility.Status != coreeval.StatusInfo || !strings.Contains(roleVisibility.Summary, "visibility evidence") {
		t.Fatalf("expected role visibility finding to be info/cautious, got %+v", roleVisibility)
	}
	if roleCompleteness := findingByRuleID(result, "ENTRA-ROLE-002"); roleCompleteness.Status != coreeval.StatusInfo {
		t.Fatalf("expected incomplete principal details finding to be info, got %+v", roleCompleteness)
	}
}

func TestEvaluateDefaultAuthStrengthCountsAsMFAEvidence(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				DisplayName:            "Privileged with auth strength",
				State:                  "enabled",
				IncludedRoles:          []string{"role-1"},
				AuthenticationStrength: "Multifactor authentication",
			},
		},
	}

	result := EvaluateDefault(bundle)
	if got := findingByRuleID(result, "ENTRA-CA-004").Status; got != coreeval.StatusPass {
		t.Fatalf("expected ENTRA-CA-004 to pass when authentication strength is present, got %s", got)
	}
}

func TestEvaluateDefaultExcludedUsersAreInformationalOnly(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				DisplayName:   "Privileged with excluded user",
				State:         "enabled",
				IncludedRoles: []string{"role-1"},
				ExcludedUsers: []string{"user-a"},
			},
		},
	}

	result := EvaluateDefault(bundle)
	f := findingByRuleID(result, "ENTRA-CA-005")
	if f.Status != coreeval.StatusInfo {
		t.Fatalf("expected informational status for exclusions evidence, got %s", f.Status)
	}
	if f.Summary == "" || !strings.Contains(f.Summary, "not proof") {
		t.Fatalf("expected summary to state limitation, got %q", f.Summary)
	}
}

func TestEvaluateDefaultRoleChecksWithCompletePrincipalDetails(t *testing.T) {
	bundle := facts.Bundle{
		DirectoryRoleDefinitions: []facts.DirectoryRoleDefinition{
			{ID: "role-1", DisplayName: "Global Administrator"},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{
				ID:                   "assign-1",
				RoleDefinitionID:     "role-1",
				RoleDisplayName:      "Global Administrator",
				PrincipalID:          "principal-1",
				PrincipalType:        "user",
				PrincipalDisplayName: "Alice",
			},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{
				PrincipalID:       "principal-1",
				RoleDefinitionIDs: []string{"role-1"},
				RoleDisplayNames:  []string{"Global Administrator"},
			},
		},
	}
	result := EvaluateDefault(bundle)
	roleVisibility := findingByRuleID(result, "ENTRA-ROLE-001")
	roleCompleteness := findingByRuleID(result, "ENTRA-ROLE-002")
	if roleVisibility.RuleID != "ENTRA-ROLE-001" {
		t.Fatalf("expected ENTRA-ROLE-001 finding, got %+v", roleVisibility)
	}
	if !strings.Contains(roleCompleteness.Summary, "included principal display details") {
		t.Fatalf("expected complete principal summary, got %q", roleCompleteness.Summary)
	}
	if len(roleCompleteness.MatchedItems) != 0 {
		t.Fatalf("expected no incomplete principal matches, got %#v", roleCompleteness.MatchedItems)
	}
}

func TestEvaluateDefaultRoleChecksWithMissingPrincipalDetails(t *testing.T) {
	bundle := facts.Bundle{
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{
				ID:               "assign-1",
				RoleDefinitionID: "role-1",
				PrincipalID:      "principal-1",
			},
		},
	}
	result := EvaluateDefault(bundle)
	roleCompleteness := findingByRuleID(result, "ENTRA-ROLE-002")
	if !strings.Contains(roleCompleteness.Summary, "incomplete principal details") {
		t.Fatalf("expected incomplete principal caution summary, got %q", roleCompleteness.Summary)
	}
	if len(roleCompleteness.MatchedItems) != 1 || roleCompleteness.MatchedItems[0] != "assign-1" {
		t.Fatalf("expected assignment id evidence, got %#v", roleCompleteness.MatchedItems)
	}
}

func TestEvaluateDefaultPrivilegedCAEvidenceChecksStayCautious(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				ID:              "policy-1",
				DisplayName:     "Privileged role MFA",
				State:           "enabled",
				IncludedRoles:   []string{"role-1"},
				ExcludedUsers:   []string{"user-a"},
				BuiltInControls: []string{"mfa"},
			},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{
				PrincipalID:       "principal-1",
				DisplayName:       "Alice",
				RoleDefinitionIDs: []string{"role-1"},
			},
		},
	}
	result := EvaluateDefault(bundle)

	coverage := findingByRuleID(result, "ENTRA-CA-006")
	exclusions := findingByRuleID(result, "ENTRA-CA-007")
	unknown := findingByRuleID(result, "ENTRA-CA-008")

	if coverage.Status != coreeval.StatusInfo || !strings.Contains(coverage.Summary, "does not prove") {
		t.Fatalf("expected cautious ENTRA-CA-006 summary, got %+v", coverage)
	}
	if exclusions.Status != coreeval.StatusInfo || !strings.Contains(exclusions.Summary, "does not assert emergency-access") {
		t.Fatalf("expected cautious ENTRA-CA-007 summary, got %+v", exclusions)
	}
	if unknown.Status != coreeval.StatusInfo || !strings.Contains(unknown.Summary, "not yet implemented") {
		t.Fatalf("expected cautious ENTRA-CA-008 summary, got %+v", unknown)
	}
	assertPrivilegedCAEvidenceDetails(t, coverage)
	assertPrivilegedCAEvidenceDetails(t, exclusions)
	assertPrivilegedCAEvidenceDetails(t, unknown)
}

func findingByRuleID(result coreeval.Result, ruleID string) coreeval.Finding {
	for _, finding := range result.Findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	return coreeval.Finding{}
}

func assertPrivilegedCAEvidenceDetails(t *testing.T, finding coreeval.Finding) {
	t.Helper()
	root, ok := finding.Details["privileged_ca_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("expected privileged_ca_evidence details on %s, got %#v", finding.RuleID, finding.Details)
	}
	summary, ok := root["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object in details on %s, got %#v", finding.RuleID, root["summary"])
	}
	for _, key := range []string{
		"total_privileged_principals",
		"principals_with_coverage_evidence",
		"principals_with_direct_exclusion_evidence",
		"principals_with_possible_exclusion_evidence",
		"principals_with_unknown_coverage",
	} {
		if _, exists := summary[key]; !exists {
			t.Fatalf("expected summary key %q on %s, got %#v", key, finding.RuleID, summary)
		}
	}
	if _, ok := root["principals"].([]map[string]any); ok {
		return
	}
	if _, ok := root["principals"].([]any); !ok {
		t.Fatalf("expected principals array in details on %s, got %#v", finding.RuleID, root["principals"])
	}
}
