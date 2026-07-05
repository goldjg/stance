package eval

import (
	"testing"

	"github.com/goldjg/stance-365/internal/facts"
)

func TestEvaluateDefault(t *testing.T) {
	bundle := facts.Bundle{
		CAPolicies: []facts.CAPolicyFact{
			{DisplayName: "Disabled policy", State: "disabled", IncludedRoles: []string{"role-1"}, BuiltInControls: []string{"mfa"}, ExcludedUsers: []string{"breakglass"}},
			{DisplayName: "Report only policy", State: "enabledForReportingButNotEnforced", IncludedRoles: []string{"role-2"}},
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
	if result.Findings[3].Status != StatusFail {
		t.Fatalf("expected mfa enforcement finding to fail, got %s", result.Findings[3].Status)
	}
	if result.Findings[4].Status != StatusFail {
		t.Fatalf("expected emergency exclusion finding to fail, got %s", result.Findings[4].Status)
	}
}
