package eval

import (
	"testing"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

func TestDeriveCollectionCompletenessSummaryCompleteForCurrentScope(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{ID: "policy-1", DisplayName: "Privileged MFA", State: "enabled"},
		},
		DirectoryRoleDefinitions: []facts.DirectoryRoleDefinition{
			{ID: "role-1", DisplayName: "Global Administrator"},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{ID: "assign-1", RoleDefinitionID: "role-1", PrincipalID: "principal-1"},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1"},
		},
		PrincipalGroupMemberships: []facts.PrincipalGroupMembership{
			{PrincipalID: "principal-1", GroupID: "group-1"},
		},
		PrincipalGroupResolutions: []facts.PrincipalGroupResolution{
			{PrincipalID: "principal-1", Resolved: true, DirectGroupCount: 1},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "complete_for_current_scope" {
		t.Fatalf("expected complete_for_current_scope, got %+v", summary)
	}
	if summary.MissingGroupResolutionCount != 0 || summary.UnresolvedGroupResolutionCount != 0 {
		t.Fatalf("expected no group-resolution gaps, got %+v", summary)
	}
}

func TestDeriveCollectionCompletenessSummaryPartialWhenGroupResolutionFailed(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{ID: "policy-1", DisplayName: "Privileged MFA", State: "enabled"},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{ID: "assign-1", RoleDefinitionID: "role-1", PrincipalID: "principal-1"},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1"},
		},
		PrincipalGroupResolutions: []facts.PrincipalGroupResolution{
			{PrincipalID: "principal-1", Resolved: false},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "partial" {
		t.Fatalf("expected partial, got %+v", summary)
	}
	if summary.UnresolvedGroupResolutionCount != 1 {
		t.Fatalf("expected unresolved count 1, got %+v", summary)
	}
}

func TestDeriveCollectionCompletenessSummaryPartialWhenGroupResolutionMissing(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{ID: "policy-1", DisplayName: "Privileged MFA", State: "enabled"},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{ID: "assign-1", RoleDefinitionID: "role-1", PrincipalID: "principal-1"},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1"},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "partial" {
		t.Fatalf("expected partial, got %+v", summary)
	}
	if summary.MissingGroupResolutionCount != 1 {
		t.Fatalf("expected missing group-resolution count 1, got %+v", summary)
	}
}

func TestDeriveCollectionCompletenessSummaryPartialWhenAssignmentsHaveNoPrivilegedPrincipals(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{ID: "policy-1", DisplayName: "Privileged MFA", State: "enabled"},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{ID: "assign-1", RoleDefinitionID: "role-1", PrincipalID: "principal-1"},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "partial" {
		t.Fatalf("expected partial, got %+v", summary)
	}
	if summary.PrivilegedPrincipalCount != 0 {
		t.Fatalf("expected privileged principal count 0, got %+v", summary)
	}
}

func TestDeriveCollectionCompletenessSummaryPartialWhenCAPolicyFactsMissing(t *testing.T) {
	bundle := facts.Bundle{
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{ID: "assign-1", RoleDefinitionID: "role-1", PrincipalID: "principal-1"},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1"},
		},
		PrincipalGroupResolutions: []facts.PrincipalGroupResolution{
			{PrincipalID: "principal-1", Resolved: true},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "partial" {
		t.Fatalf("expected partial, got %+v", summary)
	}
	if summary.ConditionalAccessPolicyCount != 0 {
		t.Fatalf("expected CA policy count 0, got %+v", summary)
	}
}

func TestDeriveCollectionCompletenessSummaryUnknownWhenRoleAssignmentsMissing(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{ID: "policy-1", DisplayName: "Privileged MFA", State: "enabled"},
		},
	}

	summary := DeriveCollectionCompletenessSummary(bundle)
	if summary.CompletenessStatus != "unknown" {
		t.Fatalf("expected unknown, got %+v", summary)
	}
}
