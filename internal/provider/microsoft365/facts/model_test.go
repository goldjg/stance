package facts

import (
	"encoding/json"
	"testing"
)

func TestBundleUnmarshalDefaultsMissingSlices(t *testing.T) {
	var bundle Bundle
	if err := json.Unmarshal([]byte(`{"service":"microsoft-graph"}`), &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if bundle.Organization == nil || bundle.CAPolicies == nil || bundle.DirectoryRoleDefinitions == nil || bundle.DirectoryRoleAssignments == nil || bundle.PrivilegedPrincipals == nil || bundle.PrincipalGroupMemberships == nil {
		t.Fatalf("expected all bundle slices to default to empty, got %+v", bundle)
	}
}

func TestDirectoryRoleDefinitionMapsOptionalBuiltIn(t *testing.T) {
	raw := []byte(`{"id":"role-1","display_name":"Global Administrator","is_built_in":true}`)
	var def DirectoryRoleDefinition
	if err := json.Unmarshal(raw, &def); err != nil {
		t.Fatalf("unmarshal role definition: %v", err)
	}
	if def.IsBuiltIn == nil || !*def.IsBuiltIn {
		t.Fatalf("expected is_built_in=true pointer, got %+v", def)
	}
}
