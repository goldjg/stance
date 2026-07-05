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
	joined := ""
	for _, p := range perms {
		joined += p + ","
	}
	if !containsPermission(perms, "RoleManagement.Read.Directory") {
		t.Fatalf("expected RoleManagement.Read.Directory in suite permissions, got %s", joined)
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

func TestForChecksRoleCheckPermissions(t *testing.T) {
	perms, err := Resolver{}.ForChecks([]string{"ENTRA-ROLE-001", "ENTRA-ROLE-002"})
	if err != nil {
		t.Fatalf("ForChecks returned error: %v", err)
	}
	if len(perms) != 1 || perms[0] != "RoleManagement.Read.Directory" {
		t.Fatalf("unexpected role-check permissions: %v", perms)
	}
}

func TestForChecksPrivilegedCAEvidencePermissions(t *testing.T) {
	perms, err := Resolver{}.ForChecks([]string{"ENTRA-CA-006", "ENTRA-CA-007", "ENTRA-CA-008"})
	if err != nil {
		t.Fatalf("ForChecks returned error: %v", err)
	}
	if !containsPermission(perms, "Policy.Read.All") || !containsPermission(perms, "RoleManagement.Read.Directory") {
		t.Fatalf("expected Policy.Read.All and RoleManagement.Read.Directory, got %v", perms)
	}
}

func containsPermission(perms []string, target string) bool {
	for _, p := range perms {
		if p == target {
			return true
		}
	}
	return false
}
