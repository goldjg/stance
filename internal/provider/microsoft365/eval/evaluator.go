package eval

import (
	coreeval "github.com/goldjg/stance/internal/core/eval"
	corerules "github.com/goldjg/stance/internal/core/rules"
	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

func EvaluateDefault(bundle facts.Bundle) coreeval.Result {
	findings := make([]coreeval.Finding, 0, 5)

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
