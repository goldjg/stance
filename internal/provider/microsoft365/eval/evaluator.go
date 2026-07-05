package eval

import (
	"fmt"
	"sort"
	"strings"

	coreeval "github.com/goldjg/stance/internal/core/eval"
	corerules "github.com/goldjg/stance/internal/core/rules"
	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

func EvaluateDefault(bundle facts.Bundle) coreeval.Result {
	findings := make([]coreeval.Finding, 0, 10)

	disabled := make([]string, 0)
	reportOnly := make([]string, 0)
	privilegedPolicies := make([]string, 0)
	privilegedWithoutMFA := make([]string, 0)
	privilegedWithUserExclusions := make([]string, 0)

	for _, policy := range bundle.CAPolicies {
		switch policy.State {
		case "disabled":
			disabled = append(disabled, policy.DisplayName)
		case "enabledForReportingButNotEnforced":
			reportOnly = append(reportOnly, policy.DisplayName)
		}
		if len(policy.IncludedRoles) > 0 {
			privilegedPolicies = append(privilegedPolicies, policy.DisplayName)
			if !hasMFAControl(policy) {
				privilegedWithoutMFA = append(privilegedWithoutMFA, policy.DisplayName)
			}
			if len(policy.ExcludedUsers) > 0 {
				privilegedWithUserExclusions = append(privilegedWithUserExclusions, policy.DisplayName)
			}
		}
	}

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-001",
		Title:        "Disabled Conditional Access policies are identified",
		Severity:     corerules.SeverityMedium,
		Status:       toStatus(len(disabled) > 0),
		Summary:      summarize("disabled policies", disabled),
		MatchedItems: disabled,
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-002",
		Title:        "Report-only Conditional Access policies are identified",
		Severity:     corerules.SeverityLow,
		Status:       toStatus(len(reportOnly) > 0),
		Summary:      summarize("report-only policies", reportOnly),
		MatchedItems: reportOnly,
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-003",
		Title:        "Conditional Access policies targeting privileged roles are identified",
		Severity:     corerules.SeverityMedium,
		Status:       toInformationalStatus(len(privilegedPolicies) > 0),
		Summary:      summarize("privileged-role-targeted policies", privilegedPolicies),
		MatchedItems: privilegedPolicies,
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-004",
		Title:        "Privileged-role Conditional Access policies enforce MFA or authentication strength",
		Severity:     corerules.SeverityHigh,
		Status:       toStatus(len(privilegedWithoutMFA) > 0),
		Summary:      summarize("privileged policies without MFA enforcement", privilegedWithoutMFA),
		MatchedItems: privilegedWithoutMFA,
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-005",
		Title:        "Privileged-role Conditional Access policies have user exclusions configured (informational)",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizeUserExclusions(privilegedWithUserExclusions),
		MatchedItems: privilegedWithUserExclusions,
	})

	privilegedCAEvidence := DerivePrivilegedCAEvidence(bundle)

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-006",
		Title:        "Privileged principal Conditional Access coverage evidence is observed",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizePrivilegedCoverageEvidence(privilegedCAEvidence),
		MatchedItems: matchedCoveragePrincipals(privilegedCAEvidence),
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-007",
		Title:        "Privileged principal Conditional Access exclusion evidence is observed",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizePrivilegedExclusionEvidence(privilegedCAEvidence),
		MatchedItems: matchedExclusionEvidence(privilegedCAEvidence),
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-CA-008",
		Title:        "Privileged principal Conditional Access coverage remains unknown from current facts",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizePrivilegedUnknownCoverage(privilegedCAEvidence),
		MatchedItems: matchedUnknownCoveragePrincipals(privilegedCAEvidence),
	})

	roleAssignments := bundle.DirectoryRoleAssignments
	privilegedPrincipals := bundle.PrivilegedPrincipals
	incompletePrincipalDetails := collectIncompletePrincipalDetails(roleAssignments)

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-ROLE-001",
		Title:        "Privileged directory role assignments are observed",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizeRoleVisibility(bundle.DirectoryRoleDefinitions, roleAssignments, privilegedPrincipals),
		MatchedItems: highImpactRoleNames(roleAssignments),
	})

	findings = append(findings, coreeval.Finding{
		RuleID:       "ENTRA-ROLE-002",
		Title:        "Privileged role assignments with incomplete principal details are observed",
		Severity:     corerules.SeverityLow,
		Status:       coreeval.StatusInfo,
		Summary:      summarizeIncompletePrincipalDetails(len(roleAssignments), len(incompletePrincipalDetails)),
		MatchedItems: incompletePrincipalDetails,
	})

	return coreeval.Result{Findings: findings}
}

func toStatus(hasMatches bool) coreeval.Status {
	if hasMatches {
		return coreeval.StatusFail
	}
	return coreeval.StatusPass
}

func toInformationalStatus(hasMatches bool) coreeval.Status {
	if hasMatches {
		return coreeval.StatusInfo
	}
	return coreeval.StatusPass
}

func summarize(kind string, matches []string) string {
	if len(matches) == 0 {
		return "No " + kind + " detected."
	}
	return "Detected " + kind + "."
}

func hasMFAControl(policy facts.CAPolicyFact) bool {
	for _, control := range policy.BuiltInControls {
		if control == "mfa" {
			return true
		}
	}
	return policy.AuthenticationStrength != ""
}

func summarizeUserExclusions(matches []string) string {
	if len(matches) == 0 {
		return "No user exclusions were observed on privileged-role-targeted policies. This does not determine emergency-access correctness."
	}
	return "Observed user exclusions on privileged-role-targeted policies. This is not proof of emergency-access coverage."
}

func summarizeRoleVisibility(definitions []facts.DirectoryRoleDefinition, assignments []facts.DirectoryRoleAssignment, principals []facts.PrivilegedPrincipal) string {
	return fmt.Sprintf(
		"Observed %d directory role definitions, %d role assignments, and %d privileged principals. This is visibility evidence and does not by itself determine emergency-access or Conditional Access coverage.",
		len(definitions),
		len(assignments),
		len(principals),
	)
}

func summarizeIncompletePrincipalDetails(totalAssignments, incompleteAssignments int) string {
	if totalAssignments == 0 {
		return "No directory role assignments were observed. Principal detail completeness could not be evaluated from assignment evidence."
	}
	if incompleteAssignments == 0 {
		return "All observed role assignments included principal display details in collected facts."
	}
	return fmt.Sprintf(
		"Observed %d of %d role assignments with incomplete principal details. This can occur for deleted objects, object-type limitations, or insufficient read scope, and is not a direct posture failure.",
		incompleteAssignments,
		totalAssignments,
	)
}

func collectIncompletePrincipalDetails(assignments []facts.DirectoryRoleAssignment) []string {
	out := make([]string, 0)
	for _, assignment := range assignments {
		if assignment.PrincipalDisplayName != "" {
			continue
		}
		out = append(out, assignment.ID)
	}
	sort.Strings(out)
	return out
}

func highImpactRoleNames(assignments []facts.DirectoryRoleAssignment) []string {
	targets := map[string]struct{}{
		"Global Administrator":             {},
		"Privileged Role Administrator":    {},
		"Conditional Access Administrator": {},
		"Security Administrator":           {},
		"Authentication Administrator":     {},
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, assignment := range assignments {
		role := assignment.RoleDisplayName
		if _, ok := targets[role]; !ok {
			continue
		}
		if _, exists := seen[role]; exists {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

func summarizePrivilegedCoverageEvidence(summary PrivilegedCAEvidenceSummary) string {
	return fmt.Sprintf(
		"Observed enforcing Conditional Access coverage evidence for %d of %d privileged principals. This is evidence-only visibility and does not prove complete effective coverage.",
		summary.PrincipalsWithCoverageEvidence,
		summary.TotalPrivilegedPrincipals,
	)
}

func summarizePrivilegedExclusionEvidence(summary PrivilegedCAEvidenceSummary) string {
	return fmt.Sprintf(
		"Observed direct exclusion evidence for %d privileged principals and possible exclusion evidence for %d privileged principals. This does not assert emergency-access or break-glass correctness.",
		summary.PrincipalsWithDirectExclusionEvidence,
		summary.PrincipalsWithPossibleExclusionEvidence,
	)
}

func summarizePrivilegedUnknownCoverage(summary PrivilegedCAEvidenceSummary) string {
	return fmt.Sprintf(
		"Coverage evidence remains unknown for %d of %d privileged principals from currently collected facts. Group expansion, emergency-access designation, and full effective-policy simulation are not yet implemented.",
		summary.PrincipalsWithUnknownCoverage,
		summary.TotalPrivilegedPrincipals,
	)
}

func matchedCoveragePrincipals(summary PrivilegedCAEvidenceSummary) []string {
	out := make([]string, 0)
	for _, principal := range summary.Principals {
		if len(principal.ObservedCoveringPolicyNames) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s", principalLabel(principal), strings.Join(principal.ObservedCoveringPolicyNames, ", ")))
	}
	sort.Strings(out)
	return out
}

func matchedExclusionEvidence(summary PrivilegedCAEvidenceSummary) []string {
	out := make([]string, 0)
	for _, principal := range summary.Principals {
		for _, line := range principal.ExclusionEvidence {
			out = append(out, fmt.Sprintf("%s: %s", principalLabel(principal), line))
		}
	}
	sort.Strings(out)
	return out
}

func matchedUnknownCoveragePrincipals(summary PrivilegedCAEvidenceSummary) []string {
	out := make([]string, 0)
	for _, principal := range summary.Principals {
		if len(principal.ObservedCoveringPolicyIDs) > 0 {
			continue
		}
		out = append(out, principalLabel(principal))
	}
	sort.Strings(out)
	return out
}

func principalLabel(principal PrivilegedPrincipalCAEvidence) string {
	if strings.TrimSpace(principal.DisplayName) != "" {
		return principal.DisplayName
	}
	if strings.TrimSpace(principal.UserPrincipalName) != "" {
		return principal.UserPrincipalName
	}
	return principal.PrincipalID
}
