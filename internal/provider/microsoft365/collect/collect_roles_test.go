package collect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goldjg/stance/internal/httpclient"
	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

func TestMapDirectoryRoleAssignment(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"assign-1",
		"roleDefinitionId":"role-1",
		"principalId":"principal-1",
		"principalType":"user"
	}`)
	got, err := mapDirectoryRoleAssignment(raw)
	if err != nil {
		t.Fatalf("mapDirectoryRoleAssignment returned error: %v", err)
	}
	if got.ID != "assign-1" || got.RoleDefinitionID != "role-1" || got.PrincipalID != "principal-1" {
		t.Fatalf("unexpected mapped assignment: %+v", got)
	}
	if !strings.Contains(got.Source, "/roleManagement/directory/roleAssignments") {
		t.Fatalf("expected source to mention role assignment endpoint, got %q", got.Source)
	}
}

func TestDerivePrivilegedPrincipals(t *testing.T) {
	out := derivePrivilegedPrincipals([]facts.DirectoryRoleAssignment{
		{
			PrincipalID:          "principal-1",
			PrincipalType:        "user",
			PrincipalDisplayName: "Alice",
			RoleDefinitionID:     "role-1",
			RoleDisplayName:      "Global Administrator",
		},
		{
			PrincipalID:          "principal-1",
			PrincipalType:        "user",
			PrincipalDisplayName: "Alice",
			RoleDefinitionID:     "role-2",
			RoleDisplayName:      "Privileged Role Administrator",
		},
	})
	if len(out) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(out))
	}
	if len(out[0].RoleDefinitionIDs) != 2 || len(out[0].RoleDisplayNames) != 2 {
		t.Fatalf("expected merged roles, got %+v", out[0])
	}
}

func TestDirectoryRoleCollectorKeepsPartialFactsWhenPrincipalLookupFails(t *testing.T) {
	var hitAssignments bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/roleManagement/directory/roleDefinitions":
			_, _ = w.Write([]byte(`{"value":[{"id":"role-1","displayName":"Global Administrator"}]}`))
		case "/v1.0/roleManagement/directory/roleAssignments":
			hitAssignments = true
			_, _ = w.Write([]byte(`{"value":[{"id":"assign-1","roleDefinitionId":"role-1","principalId":"missing","principalType":"user"}]}`))
		case "/v1.0/directoryObjects/missing":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
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
	bundle := facts.NewBundle()
	err := DirectoryRoleCollector{}.Collect(context.Background(), client, &bundle)
	if err != nil {
		t.Fatalf("DirectoryRoleCollector.Collect returned error: %v", err)
	}
	if !hitAssignments {
		t.Fatalf("expected role assignments endpoint to be called")
	}
	if len(bundle.DirectoryRoleAssignments) != 1 {
		t.Fatalf("expected 1 assignment fact, got %d", len(bundle.DirectoryRoleAssignments))
	}
	if bundle.DirectoryRoleAssignments[0].PrincipalDisplayName != "" {
		t.Fatalf("expected missing display name when lookup fails, got %+v", bundle.DirectoryRoleAssignments[0])
	}
}

func TestCollectDirectoryRoleDefinitionsPaginates(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/roleManagement/directory/roleDefinitions":
			_, _ = w.Write([]byte(`{"value":[{"id":"role-1","displayName":"Global Administrator"}],"@odata.nextLink":"` + serverURL + `/page2"}`))
		case "/page2":
			_, _ = w.Write([]byte(`{"value":[{"id":"role-2","displayName":"Security Administrator"}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	client := graph.NewClient(
		srv.URL,
		staticTokenProvider{},
		httpclient.New("STANCE/test").WithHTTPClient(srv.Client()),
	)
	defs, err := collectDirectoryRoleDefinitions(context.Background(), client)
	if err != nil {
		t.Fatalf("collectDirectoryRoleDefinitions returned error: %v", err)
	}
	if len(defs) != 2 {
		t.Fatalf("expected 2 role definitions from paginated response, got %d", len(defs))
	}
}
