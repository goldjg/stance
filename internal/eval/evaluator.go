package eval

import (
	"github.com/goldjg/stance-365/internal/facts"
	"github.com/goldjg/stance-365/internal/rules"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

type Finding struct {
	RuleID       string         `json:"rule_id"`
	Title        string         `json:"title"`
	Severity     rules.Severity `json:"severity"`
	Status       Status         `json:"status"`
	Summary      string         `json:"summary"`
	MatchedItems []string       `json:"matched_items,omitempty"`
}

type Result struct {
	Findings []Finding `json:"findings"`
}

func EvaluateDefault(bundle facts.Bundle) Result {
	findings := make([]Finding, 0, 5)

	disabled := make([]string, 0)
	reportOnly := make([]string, 0)
	privilegedPolicies := make([]string, 0)
	privilegedWithoutMFA := make([]string, 0)
	privilegedWithoutEmergencyExclusion := make([]string, 0)

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
			if len(policy.ExcludedUsers) == 0 {
				privilegedWithoutEmergencyExclusion = append(privilegedWithoutEmergencyExclusion, policy.DisplayName)
			}
		}
	}

	findings = append(findings, Finding{
		RuleID:       "ENTRA-CA-001",
		Title:        "Disabled Conditional Access policies are identified",
		Severity:     rules.SeverityMedium,
		Status:       toStatus(len(disabled) > 0),
		Summary:      summarize("disabled policies", disabled),
		MatchedItems: disabled,
	})

	findings = append(findings, Finding{
		RuleID:       "ENTRA-CA-002",
		Title:        "Report-only Conditional Access policies are identified",
		Severity:     rules.SeverityLow,
		Status:       toStatus(len(reportOnly) > 0),
		Summary:      summarize("report-only policies", reportOnly),
		MatchedItems: reportOnly,
	})

	findings = append(findings, Finding{
		RuleID:       "ENTRA-CA-003",
		Title:        "Conditional Access policies targeting privileged roles are identified",
		Severity:     rules.SeverityMedium,
		Status:       toInformationalStatus(len(privilegedPolicies) > 0),
		Summary:      summarize("privileged-role-targeted policies", privilegedPolicies),
		MatchedItems: privilegedPolicies,
	})

	findings = append(findings, Finding{
		RuleID:       "ENTRA-CA-004",
		Title:        "Privileged-role Conditional Access policies enforce MFA or authentication strength",
		Severity:     rules.SeverityHigh,
		Status:       toStatus(len(privilegedWithoutMFA) > 0),
		Summary:      summarize("privileged policies without MFA enforcement", privilegedWithoutMFA),
		MatchedItems: privilegedWithoutMFA,
	})

	findings = append(findings, Finding{
		RuleID:       "ENTRA-CA-005",
		Title:        "Emergency access exclusions are present for privileged-role Conditional Access policies",
		Severity:     rules.SeverityHigh,
		Status:       toStatus(len(privilegedWithoutEmergencyExclusion) > 0),
		Summary:      summarize("privileged policies without emergency-access exclusion", privilegedWithoutEmergencyExclusion),
		MatchedItems: privilegedWithoutEmergencyExclusion,
	})

	return Result{Findings: findings}
}

func toStatus(hasMatches bool) Status {
	if hasMatches {
		return StatusFail
	}
	return StatusPass
}

func toInformationalStatus(hasMatches bool) Status {
	if hasMatches {
		return StatusInfo
	}
	return StatusPass
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
