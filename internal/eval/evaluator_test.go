package eval

import (
	"strings"
	"testing"

	"github.com/goldjg/stance-365/internal/facts"
	"github.com/goldjg/stance-365/internal/rules"
)

func TestEvaluateDefault(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{DisplayName: "Disabled policy", State: "disabled", IncludedRoles: []string{"role-1"}, BuiltInControls: []string{"mfa"}, ExcludedUsers: []string{"breakglass"}},
			{DisplayName: "Report only policy", State: "enabledForReportingButNotEnforced", IncludedRoles: []string{"role-2"}, AuthenticationStrength: "High assurance"},
		},
	}

	result := EvaluateDefault(bundle)
	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Status != StatusFail {
		t.Fatalf("expected first finding to fail, got %s", result.Findings[0].Status)
	}
	if result.Findings[1].Status != StatusFail {
		t.Fatalf("expected second finding to fail, got %s", result.Findings[1].Status)
	}
	if result.Findings[2].Status != StatusInfo {
		t.Fatalf("expected privileged detection to be info, got %s", result.Findings[2].Status)
	}
	if result.Findings[3].Status != StatusPass {
		t.Fatalf("expected mfa/auth strength enforcement finding to pass, got %s", result.Findings[3].Status)
	}
	if result.Findings[4].Status != StatusInfo {
		t.Fatalf("expected exclusions finding to be informational, got %s", result.Findings[4].Status)
	}
	if result.Findings[4].Severity != rules.SeverityLow {
		t.Fatalf("expected exclusions finding severity low, got %s", result.Findings[4].Severity)
	}
	if result.Findings[4].Summary == "" || !strings.Contains(result.Findings[4].Summary, "not proof") {
		t.Fatalf("expected cautious exclusion summary, got %q", result.Findings[4].Summary)
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
	if got := result.Findings[3].Status; got != StatusPass {
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
	if f.Status != StatusInfo {
		t.Fatalf("expected informational status for exclusions evidence, got %s", f.Status)
	}
	if f.Summary == "" || !strings.Contains(f.Summary, "not proof") {
		t.Fatalf("expected summary to state limitation, got %q", f.Summary)
	}
}
