package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type TestResult struct {
	Provider   string
	TenantID   string
	StatusCode int
}

type GraphTester struct {
	httpClient      *http.Client
	provider        TokenProvider
	organizationURL string
	tenantID        string
}

func NewGraphTester(provider TokenProvider) *GraphTester {
	return &GraphTester{
		httpClient:      &http.Client{},
		provider:        provider,
		organizationURL: graphOrganizationURLFromEnv(),
		tenantID:        strings.TrimSpace(os.Getenv("STANCE_TENANT_ID")),
	}
}

func (t *GraphTester) Test(ctx context.Context) (TestResult, error) {
	tok, err := t.provider.AcquireToken(ctx)
	if err != nil {
		return TestResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.organizationURL, nil)
	if err != nil {
		return TestResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "STANCE/"+os.Getenv("STANCE_VERSION"))

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return TestResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return TestResult{}, fmt.Errorf("graph test endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return TestResult{
		Provider:   t.provider.Name(),
		TenantID:   t.tenantID,
		StatusCode: resp.StatusCode,
	}, nil
}

func graphOrganizationURLFromEnv() string {
	v := strings.TrimSpace(os.Getenv("STANCE_GRAPH_ORGANIZATION_URL"))
	if v == "" {
		return "https://graph.microsoft.com/v1.0/organization?$top=1"
	}
	return v
}
