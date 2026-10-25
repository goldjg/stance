package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goldjg/stance/internal/httpclient"
	"github.com/goldjg/stance/internal/provider/microsoft365/auth"
)

type fakeTokenProvider struct{}

func (fakeTokenProvider) AcquireToken(context.Context) (auth.Token, error) {
	return auth.Token{AccessToken: "test-token"}, nil
}

func (fakeTokenProvider) Name() string { return "fake" }

func TestCollectPaginated(t *testing.T) {
	var calls int32
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			_, _ = w.Write([]byte(`{"value":[{"id":"1"}],"@odata.nextLink":"` + serverURL + `/page2"}`))
		case 2:
			_, _ = w.Write([]byte(`{"value":[{"id":"2"}]}`))
		default:
			t.Fatalf("unexpected call %d", n)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	client := NewClient(
		srv.URL,
		fakeTokenProvider{},
		httpclient.New("STANCE/test").WithHTTPClient(srv.Client()),
	)

	items, err := client.CollectPaginated(context.Background(), "/v1.0/policies/conditionalAccessPolicies")
	if err != nil {
		t.Fatalf("CollectPaginated returned error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	var decoded map[string]string
	if err := json.Unmarshal(items[0], &decoded); err != nil {
		t.Fatalf("unmarshal first item: %v", err)
	}
	if decoded["id"] != "1" {
		t.Fatalf("unexpected first item: %v", decoded)
	}
}

func TestGetJSONErrorIncludesStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	client := NewClient(
		srv.URL,
		fakeTokenProvider{},
		httpclient.New("STANCE/test").WithHTTPClient(srv.Client()),
	)

	var out map[string]any
	err := client.GetJSON(context.Background(), "/v1.0/organization", &out)
	if err == nil {
		t.Fatalf("expected error for forbidden response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected status code in error, got: %v", err)
	}
}

func TestCollectPaginatedRelativeNextLink(t *testing.T) {
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("unexpected auth header: %q", got)
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			_, _ = w.Write([]byte(`{"value":[{"id":"1"}],"@odata.nextLink":"/v1.0/page2?$skiptoken=opaque"}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"2"}]}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, fakeTokenProvider{}, httpclient.New("STANCE/test").WithHTTPClient(srv.Client()))

	items, err := client.CollectPaginated(context.Background(), "/v1.0/page1")
	if err != nil {
		t.Fatalf("CollectPaginated returned error: %v", err)
	}
	if len(items) != 2 || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected two items across two same-origin requests, got %d items and %d calls", len(items), calls)
	}
}

func TestCollectPaginatedRejectsUntrustedNextLinks(t *testing.T) {
	testCases := []struct {
		name string
		link func(string) string
	}{
		{name: "different HTTPS origin", link: func(other string) string { return other + "/steal" }},
		{name: "HTTP downgrade", link: func(other string) string { return "http" + strings.TrimPrefix(other, "https") + "/steal" }},
		{name: "unexpected scheme", link: func(other string) string { return "ftp" + strings.TrimPrefix(other, "https") + "/steal" }},
		{name: "malformed URL", link: func(string) string { return "https://%zz/invalid" }},
		{name: "userinfo", link: func(other string) string {
			return strings.Replace(other, "https://", "https://user:password@", 1) + "/steal"
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var externalCalls int32
			external := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&externalCalls, 1)
				w.WriteHeader(http.StatusOK)
			}))
			defer external.Close()

			graph := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("unexpected auth header: %q", got)
				}
				_, _ = w.Write([]byte(`{"value":[],"@odata.nextLink":"` + tc.link(external.URL) + `"}`))
			}))
			defer graph.Close()
			client := NewClient(graph.URL, fakeTokenProvider{}, httpclient.New("STANCE/test").WithHTTPClient(graph.Client()))

			_, err := client.CollectPaginated(context.Background(), "/v1.0/page1")
			if err == nil {
				t.Fatal("expected untrusted pagination URL to be rejected")
			}
			if atomic.LoadInt32(&externalCalls) != 0 {
				t.Fatalf("untrusted destination received %d requests", externalCalls)
			}
		})
	}
}

func TestRedirectCannotSendGraphTokenOffOrigin(t *testing.T) {
	var externalCalls int32
	external := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&externalCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer external.Close()

	graph := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("legitimate Graph request missing bearer token")
		}
		http.Redirect(w, r, external.URL+"/redirect-target", http.StatusFound)
	}))
	defer graph.Close()
	client := NewClient(graph.URL, fakeTokenProvider{}, httpclient.New("STANCE/test").WithHTTPClient(graph.Client()))

	var out map[string]any
	err := client.GetJSON(context.Background(), "/v1.0/redirect", &out)
	if err == nil || !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("expected off-origin redirect to be rejected, got %v", err)
	}
	if atomic.LoadInt32(&externalCalls) != 0 {
		t.Fatalf("external destination received %d requests", externalCalls)
	}
}

func TestGetJSONRequiresHTTPSGraphEndpoint(t *testing.T) {
	client := NewClient("http://graph.example.test", fakeTokenProvider{}, nil)
	var out map[string]any
	if err := client.GetJSON(context.Background(), "/v1.0/organization", &out); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTP Graph endpoint to be rejected, got %v", err)
	}
}
