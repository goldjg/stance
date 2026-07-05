package collect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goldjg/stance/internal/httpclient"
	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

func TestMapDirectPrincipalGroupMembershipIgnoresNonGroupObjects(t *testing.T) {
	principal := facts.PrivilegedPrincipal{PrincipalID: "principal-1", PrincipalType: "user"}
	membership, ok, err := mapDirectPrincipalGroupMembership(
		json.RawMessage(`{"id":"role-1","@odata.type":"#microsoft.graph.directoryRole","displayName":"Global Administrator"}`),
		principal,
	)
	if err != nil {
		t.Fatalf("mapDirectPrincipalGroupMembership returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected non-group object to be ignored, got %+v", membership)
	}
}

func TestCollectDirectGroupMembershipsForPrincipalPaginates(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/directoryObjects/principal-1/memberOf":
			_, _ = w.Write([]byte(`{"value":[{"id":"group-1","@odata.type":"#microsoft.graph.group","displayName":"Admins"}],"@odata.nextLink":"` + serverURL + `/page2"}`))
		case "/page2":
			_, _ = w.Write([]byte(`{"value":[{"id":"group-2","@odata.type":"#microsoft.graph.group","displayName":"Security"}]}`))
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
	principal := facts.PrivilegedPrincipal{PrincipalID: "principal-1", PrincipalType: "user"}
	out, err := collectDirectGroupMembershipsForPrincipal(context.Background(), client, principal)
	if err != nil {
		t.Fatalf("collectDirectGroupMembershipsForPrincipal returned error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 paginated group memberships, got %d", len(out))
	}
	if out[0].GroupType != "group" {
		t.Fatalf("expected normalized group_type, got %+v", out[0])
	}
}

func TestPrivilegedPrincipalGroupMembershipCollectorContinuesOnPrincipalFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/directoryObjects/principal-ok/memberOf":
			_, _ = w.Write([]byte(`{"value":[{"id":"group-1","@odata.type":"#microsoft.graph.group","displayName":"Admins"}]}`))
		case "/v1.0/directoryObjects/principal-fail/memberOf":
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
	bundle.PrivilegedPrincipals = []facts.PrivilegedPrincipal{
		{PrincipalID: "principal-ok", PrincipalType: "user"},
		{PrincipalID: "principal-fail", PrincipalType: "user"},
	}
	err := PrivilegedPrincipalGroupMembershipCollector{}.Collect(context.Background(), client, &bundle)
	if err != nil {
		t.Fatalf("PrivilegedPrincipalGroupMembershipCollector.Collect returned error: %v", err)
	}
	if len(bundle.PrincipalGroupMemberships) != 1 {
		t.Fatalf("expected collector to keep partial facts when one principal fails, got %d", len(bundle.PrincipalGroupMemberships))
	}
	if bundle.PrincipalGroupMemberships[0].PrincipalID != "principal-ok" {
		t.Fatalf("unexpected membership principal: %+v", bundle.PrincipalGroupMemberships[0])
	}
}
