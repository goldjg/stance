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
	if len(result.Findings) != 7 {
		t.Fatalf("expected 7 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Status != coreeval.StatusFail {
		t.Fatalf("expected first finding to fail, got %s", result.Findings[0].Status)
	}
	if result.Findings[1].Status != coreeval.StatusFail {
		t.Fatalf("expected second finding to fail, got %s", result.Findings[1].Status)
	}
	if result.Findings[2].Status != coreeval.StatusInfo {
		t.Fatalf("expected privileged detection to be info, got %s", result.Findings[2].Status)
	}
	if result.Findings[3].Status != coreeval.StatusPass {
		t.Fatalf("expected mfa/auth strength enforcement finding to pass, got %s", result.Findings[3].Status)
	}
	if result.Findings[4].Status != coreeval.StatusInfo {
		t.Fatalf("expected exclusions finding to be informational, got %s", result.Findings[4].Status)
	}
	if result.Findings[4].Severity != corerules.SeverityLow {
		t.Fatalf("expected exclusions finding severity low, got %s", result.Findings[4].Severity)
	}
	if result.Findings[4].Summary == "" || !strings.Contains(result.Findings[4].Summary, "not proof") {
		t.Fatalf("expected cautious exclusion summary, got %q", result.Findings[4].Summary)
	}
	if result.Findings[5].Status != coreeval.StatusInfo || !strings.Contains(result.Findings[5].Summary, "visibility evidence") {
		t.Fatalf("expected role visibility finding to be info/cautious, got %+v", result.Findings[5])
	}
	if result.Findings[6].Status != coreeval.StatusInfo {
		t.Fatalf("expected incomplete principal details finding to be info, got %+v", result.Findings[6])
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
	if got := result.Findings[3].Status; got != coreeval.StatusPass {
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
	f := result.Findings[4]
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
	roleVisibility := result.Findings[5]
	roleCompleteness := result.Findings[6]
	if roleVisibility.RuleID != "ENTRA-ROLE-001" {
		t.Fatalf("expected ENTRA-ROLE-001 in slot 6, got %s", roleVisibility.RuleID)
	}
	if roleCompleteness.RuleID != "ENTRA-ROLE-002" {
		t.Fatalf("expected ENTRA-ROLE-002 in slot 7, got %s", roleCompleteness.RuleID)
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
	roleCompleteness := result.Findings[6]
	if roleCompleteness.RuleID != "ENTRA-ROLE-002" {
		t.Fatalf("expected ENTRA-ROLE-002, got %s", roleCompleteness.RuleID)
	}
	if !strings.Contains(roleCompleteness.Summary, "incomplete principal details") {
		t.Fatalf("expected incomplete principal caution summary, got %q", roleCompleteness.Summary)
	}
	if len(roleCompleteness.MatchedItems) != 1 || roleCompleteness.MatchedItems[0] != "assign-1" {
		t.Fatalf("expected assignment id evidence, got %#v", roleCompleteness.MatchedItems)
	}
}
