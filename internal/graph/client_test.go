package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goldjg/stance-365/internal/auth"
	"github.com/goldjg/stance-365/internal/httpclient"
)

type fakeTokenProvider struct{}

func (fakeTokenProvider) AcquireToken(context.Context) (auth.Token, error) {
	return auth.Token{AccessToken: "test-token"}, nil
}

func (fakeTokenProvider) Name() string { return "fake" }

func TestCollectPaginated(t *testing.T) {
	var calls int32
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
