package collect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/goldjg/stance/internal/httpclient"
	"github.com/goldjg/stance/internal/provider/microsoft365/auth"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

type staticTokenProvider struct{}

func (staticTokenProvider) AcquireToken(context.Context) (auth.Token, error) {
	return auth.Token{AccessToken: "token"}, nil
}

func (staticTokenProvider) Name() string { return "static" }

func TestMapCAPolicyFromFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "conditional_access_policy.json")
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	fact, err := mapCAPolicy(json.RawMessage(b))
	if err != nil {
		t.Fatalf("mapCAPolicy returned error: %v", err)
	}
	if fact.ID != "policy-1" {
		t.Fatalf("unexpected policy id: %+v", fact)
	}
	if len(fact.BuiltInControls) != 1 || fact.BuiltInControls[0] != "mfa" {
		t.Fatalf("unexpected controls: %+v", fact)
	}
	if fact.AuthenticationStrength != "Multifactor authentication" {
		t.Fatalf("expected authentication strength to map from grantControls, got: %+v", fact)
	}
}

func TestRunDefaultCollectsOrganizationAndPolicies(t *testing.T) {
	var hitOrg, hitCA, hitRoleDefs, hitRoleAssignments, hitPrincipal bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/organization":
			hitOrg = true
			_, _ = w.Write([]byte(`{"value":[{"id":"org-1","displayName":"Contoso","tenantType":"AAD"}]}`))
		case "/v1.0/identity/conditionalAccess/policies":
			hitCA = true
			_, _ = w.Write([]byte(`{"value":[{"id":"policy-1","displayName":"P1","state":"enabled","conditions":{"users":{}}}]}`))
		case "/v1.0/roleManagement/directory/roleDefinitions":
			hitRoleDefs = true
			_, _ = w.Write([]byte(`{"value":[{"id":"role-1","displayName":"Global Administrator","isBuiltIn":true}]}`))
		case "/v1.0/roleManagement/directory/roleAssignments":
			hitRoleAssignments = true
			_, _ = w.Write([]byte(`{"value":[{"id":"assign-1","roleDefinitionId":"role-1","principalId":"principal-1","principalType":"user"}]}`))
		case "/v1.0/directoryObjects/principal-1":
			hitPrincipal = true
			_, _ = w.Write([]byte(`{"id":"principal-1","@odata.type":"#microsoft.graph.user","displayName":"Alice Admin","userPrincipalName":"alice@contoso.com"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	client := graph.NewClient(
		srv.URL,
		staticTokenProvider{},
		httpclient.New("STANCE/test").WithHTTPClient(srv.Client()),
	)

	bundle, err := RunDefault(context.Background(), client)
	if err != nil {
		t.Fatalf("RunDefault returned error: %v", err)
	}
	if !hitOrg || !hitCA || !hitRoleDefs || !hitRoleAssignments || !hitPrincipal {
		t.Fatalf(
			"expected org/ca/role endpoints to be called, hitOrg=%v hitCA=%v hitRoleDefs=%v hitRoleAssignments=%v hitPrincipal=%v",
			hitOrg,
			hitCA,
			hitRoleDefs,
			hitRoleAssignments,
			hitPrincipal,
		)
	}
	if len(bundle.Organization) != 1 {
		t.Fatalf("expected 1 organization record, got %d", len(bundle.Organization))
	}
	if len(bundle.CAPolicies) != 1 {
		t.Fatalf("expected 1 ca policy record, got %d", len(bundle.CAPolicies))
	}
	if len(bundle.DirectoryRoleDefinitions) != 1 {
		t.Fatalf("expected 1 role definition record, got %d", len(bundle.DirectoryRoleDefinitions))
	}
	if len(bundle.DirectoryRoleAssignments) != 1 {
		t.Fatalf("expected 1 role assignment record, got %d", len(bundle.DirectoryRoleAssignments))
	}
	if len(bundle.PrivilegedPrincipals) != 1 {
		t.Fatalf("expected 1 privileged principal, got %d", len(bundle.PrivilegedPrincipals))
	}
}
