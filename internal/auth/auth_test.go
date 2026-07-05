package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

type fakeProvider struct {
	token Token
	err   error
	name  string
}

func (f fakeProvider) AcquireToken(context.Context) (Token, error) {
	return f.token, f.err
}

func (f fakeProvider) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func TestConfigFromEnvRejectsAmbiguousAuth(t *testing.T) {
	t.Setenv("STANCE_TENANT_ID", "tenant")
	t.Setenv("STANCE_CLIENT_ID", "client")
	t.Setenv("STANCE_CLIENT_SECRET", "secret")
	t.Setenv("STANCE_CLIENT_ASSERTION", "assertion")

	_, err := ConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous auth error, got %v", err)
	}
}

func TestTokenProviderClientSecretFlow(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		got, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	provider := &tokenProvider{
		name:       "client_secret",
		httpClient: srv.Client(),
		tokenURL:   srv.URL,
		values: url.Values{
			"client_id":     []string{"cid"},
			"scope":         []string{defaultScope},
			"grant_type":    []string{"client_credentials"},
			"client_secret": []string{"secret"},
		},
	}
	tok, err := provider.AcquireToken(context.Background())
	if err != nil {
		t.Fatalf("AcquireToken returned error: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Fatalf("unexpected token: %+v", tok)
	}
	if got.Get("client_secret") != "secret" {
		t.Fatalf("expected client_secret flow, got values: %v", got)
	}
}

func TestGraphTesterUsesMockProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mocked-token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	tester := &GraphTester{
		httpClient:      srv.Client(),
		provider:        fakeProvider{token: Token{AccessToken: "mocked-token"}, name: "mock"},
		organizationURL: srv.URL,
		tenantID:        "00000000-0000-0000-0000-000000000000",
	}
	result, err := tester.Test(context.Background())
	if err != nil {
		t.Fatalf("Test returned error: %v", err)
	}
	if result.Provider != "mock" {
		t.Fatalf("unexpected provider: %+v", result)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %+v", result)
	}
}

func TestRedact(t *testing.T) {
	in := "token endpoint returned status 400: client_secret=s3cr3t access_token: abc123"
	out := Redact(in)
	if strings.Contains(out, "s3cr3t") || strings.Contains(out, "abc123") {
		t.Fatalf("redaction failed: %q", out)
	}
}

func TestNewTokenProviderFromFederatedTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/assertion.jwt"
	if err := os.WriteFile(path, []byte("jwt-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := Config{
		TenantID:           "tenant",
		ClientID:           "client",
		TokenURL:           "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		Scope:              defaultScope,
		FederatedTokenFile: path,
	}

	p, err := NewTokenProvider(cfg)
	if err != nil {
		t.Fatalf("NewTokenProvider returned error: %v", err)
	}
	if p.Name() != "workload_identity" {
		t.Fatalf("unexpected provider name: %s", p.Name())
	}
}
