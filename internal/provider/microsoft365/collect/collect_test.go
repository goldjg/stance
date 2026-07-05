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
	var hitOrg, hitCA bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/organization":
			hitOrg = true
			_, _ = w.Write([]byte(`{"value":[{"id":"org-1","displayName":"Contoso","tenantType":"AAD"}]}`))
		case "/v1.0/identity/conditionalAccess/policies":
			hitCA = true
			_, _ = w.Write([]byte(`{"value":[{"id":"policy-1","displayName":"P1","state":"enabled","conditions":{"users":{}}}]}`))
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
	if !hitOrg || !hitCA {
		t.Fatalf("expected both org and ca endpoints to be called, hitOrg=%v hitCA=%v", hitOrg, hitCA)
	}
	if len(bundle.Organization) != 1 {
		t.Fatalf("expected 1 organization record, got %d", len(bundle.Organization))
	}
	if len(bundle.CAPolicies) != 1 {
		t.Fatalf("expected 1 ca policy record, got %d", len(bundle.CAPolicies))
	}
}
