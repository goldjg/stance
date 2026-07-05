package eval

import (
	"strings"
	"testing"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

func TestDerivePrivilegedCAEvidenceRoleTargetedCoverage(t *testing.T) {
	summary := DerivePrivilegedCAEvidence(facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				ID:              "policy-1",
				DisplayName:     "Privileged role MFA",
				State:           "enabled",
				IncludedRoles:   []string{"role-1"},
				BuiltInControls: []string{"mfa"},
			},
		},
		DirectoryRoleAssignments: []facts.DirectoryRoleAssignment{
			{PrincipalID: "principal-1", RoleDefinitionID: "role-1", RoleDisplayName: "Global Administrator"},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1", DisplayName: "Alice", RoleDefinitionIDs: []string{"role-1"}, RoleDisplayNames: []string{"Global Administrator"}},
		},
	})

	if summary.PrincipalsWithCoverageEvidence != 1 {
		t.Fatalf("expected coverage evidence for one principal, got %+v", summary)
	}
	if summary.PrincipalsWithUnknownCoverage != 0 {
		t.Fatalf("expected no unknown coverage principals, got %+v", summary)
	}
	if len(summary.Principals) != 1 || len(summary.Principals[0].ObservedCoveringPolicyNames) != 1 {
		t.Fatalf("expected one covering policy on principal evidence, got %+v", summary.Principals)
	}
}

func TestDerivePrivilegedCAEvidenceUnknownWhenNoCoverageObserved(t *testing.T) {
	summary := DerivePrivilegedCAEvidence(facts.Bundle{
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1", DisplayName: "Alice", RoleDefinitionIDs: []string{"role-1"}},
		},
	})

	if summary.PrincipalsWithCoverageEvidence != 0 || summary.PrincipalsWithUnknownCoverage != 1 {
		t.Fatalf("expected unknown coverage for single principal, got %+v", summary)
	}
	if len(summary.Principals[0].Limitations) == 0 {
		t.Fatalf("expected explicit limitations in evidence model")
	}
}

func TestDerivePrivilegedCAEvidenceReportOnlyIsNotEnforcementEvidence(t *testing.T) {
	summary := DerivePrivilegedCAEvidence(facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				ID:              "policy-1",
				DisplayName:     "Report-only privileged role policy",
				State:           "enabledForReportingButNotEnforced",
				IncludedRoles:   []string{"role-1"},
				BuiltInControls: []string{"mfa"},
			},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1", DisplayName: "Alice", RoleDefinitionIDs: []string{"role-1"}},
		},
	})

	if summary.PrincipalsWithCoverageEvidence != 0 || summary.PrincipalsWithUnknownCoverage != 1 {
		t.Fatalf("expected report-only policy to be excluded from enforcement evidence, got %+v", summary)
	}
}

func TestDerivePrivilegedCAEvidenceDirectExclusionByPrincipalID(t *testing.T) {
	summary := DerivePrivilegedCAEvidence(facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				ID:              "policy-1",
				DisplayName:     "Privileged role with exclusion",
				State:           "enabled",
				IncludedRoles:   []string{"role-1"},
				ExcludedUsers:   []string{"principal-1"},
				BuiltInControls: []string{"mfa"},
			},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1", DisplayName: "Alice", RoleDefinitionIDs: []string{"role-1"}},
		},
	})

	if summary.PrincipalsWithDirectExclusionEvidence != 1 {
		t.Fatalf("expected direct exclusion evidence, got %+v", summary)
	}
	if len(summary.Principals[0].ExclusionEvidence) == 0 || !strings.Contains(strings.Join(summary.Principals[0].ExclusionEvidence, " "), "Direct exclusion observed") {
		t.Fatalf("expected direct exclusion evidence line, got %+v", summary.Principals[0].ExclusionEvidence)
	}
}

func TestDerivePrivilegedCAEvidencePossibleExclusionWhenPrincipalCannotBeProven(t *testing.T) {
	summary := DerivePrivilegedCAEvidence(facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{
				ID:              "policy-1",
				DisplayName:     "Privileged role with user exclusion list",
				State:           "enabled",
				IncludedRoles:   []string{"role-1"},
				ExcludedUsers:   []string{"some-other-user"},
				BuiltInControls: []string{"mfa"},
			},
		},
		PrivilegedPrincipals: []facts.PrivilegedPrincipal{
			{PrincipalID: "principal-1", DisplayName: "Alice", RoleDefinitionIDs: []string{"role-1"}},
		},
	})

	if summary.PrincipalsWithDirectExclusionEvidence != 0 || summary.PrincipalsWithPossibleExclusionEvidence != 1 {
		t.Fatalf("expected possible-only exclusion evidence, got %+v", summary)
	}
	if len(summary.Principals[0].ExclusionEvidence) == 0 || !strings.Contains(strings.Join(summary.Principals[0].ExclusionEvidence, " "), "Possible exclusion observed") {
		t.Fatalf("expected possible exclusion evidence line, got %+v", summary.Principals[0].ExclusionEvidence)
	}
}

func TestNormalizePrivilegedCAEvidenceSummarySortsNestedCollections(t *testing.T) {
	normalized := normalizePrivilegedCAEvidenceSummary(PrivilegedCAEvidenceSummary{
		Principals: []PrivilegedPrincipalCAEvidence{
			{
				PrincipalID:                  "principal-b",
				RoleDisplayNames:             []string{"Role Z", "Role A"},
				ObservedCoveringPolicyIDs:    []string{"policy-b", "policy-a"},
				ObservedCoveringPolicyNames:  []string{"Policy Z", "Policy A"},
				ObservedExcludingPolicyIDs:   []string{"exclude-b", "exclude-a"},
				ObservedExcludingPolicyNames: []string{"Exclude Z", "Exclude A"},
				CoverageEvidence:             []string{"z line", "a line"},
				ExclusionEvidence:            []string{"z exclude", "a exclude"},
				Limitations:                  []string{"z limitation", "a limitation"},
			},
			{
				PrincipalID:      "principal-a",
				RoleDisplayNames: []string{"Role B"},
			},
		},
	})

	if got := normalized.Principals[0].PrincipalID; got != "principal-a" {
		t.Fatalf("expected principals sorted by principal id, got %s", got)
	}
	if strings.Join(normalized.Principals[1].RoleDisplayNames, ",") != "Role A,Role Z" {
		t.Fatalf("expected role names sorted, got %#v", normalized.Principals[1].RoleDisplayNames)
	}
	if strings.Join(normalized.Principals[1].ObservedCoveringPolicyIDs, ",") != "policy-a,policy-b" {
		t.Fatalf("expected covering policy ids sorted, got %#v", normalized.Principals[1].ObservedCoveringPolicyIDs)
	}
	if strings.Join(normalized.Principals[1].CoverageEvidence, ",") != "a line,z line" {
		t.Fatalf("expected coverage evidence sorted, got %#v", normalized.Principals[1].CoverageEvidence)
	}
	if strings.Join(normalized.Principals[1].Limitations, ",") != "a limitation,z limitation" {
		t.Fatalf("expected limitations sorted, got %#v", normalized.Principals[1].Limitations)
	}
}
