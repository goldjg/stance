package catalog

import "testing"

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
	if suite.CheckCount != 5 {
		t.Fatalf("expected 5 checks in entra suite, got %d", suite.CheckCount)
	}
}

func TestChecksFromRuleMetadata(t *testing.T) {
	checks := Checks()
	if len(checks) != 5 {
		t.Fatalf("expected 5 checks, got %d", len(checks))
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
}
