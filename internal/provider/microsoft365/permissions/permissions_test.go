package permissions

import "testing"

func TestForSuite(t *testing.T) {
	perms, err := Resolver{}.ForSuite("entra")
	if err != nil {
		t.Fatalf("ForSuite returned error: %v", err)
	}
	if len(perms) == 0 {
		t.Fatalf("expected permissions for entra suite")
	}
}

func TestForChecks(t *testing.T) {
	perms, err := Resolver{}.ForChecks([]string{"ENTRA-CA-001", "ENTRA-CA-002"})
	if err != nil {
		t.Fatalf("ForChecks returned error: %v", err)
	}
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Fatalf("unexpected permissions: %v", perms)
	}
}
