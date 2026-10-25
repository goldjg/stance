package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goldjg/stance/internal/httpclient"
	"github.com/goldjg/stance/internal/provider/microsoft365/auth"
)

type Client struct {
	baseURL       string
	tokenProvider auth.TokenProvider
	httpClient    *httpclient.Client
}

func NewClient(baseURL string, tokenProvider auth.TokenProvider, httpClient *httpclient.Client) *Client {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if b == "" {
		b = "https://graph.microsoft.com"
	}
	if httpClient == nil {
		httpClient = httpclient.New("STANCE/dev")
	}
	return &Client{
		baseURL:       b,
		tokenProvider: tokenProvider,
		httpClient:    httpClient,
	}
}

func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	body, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	return nil
}

func (c *Client) CollectPaginated(ctx context.Context, path string) ([]json.RawMessage, error) {
	items := make([]json.RawMessage, 0)
	next := path
	for next != "" {
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := c.GetJSON(ctx, next, &page); err != nil {
			return nil, err
		}
		items = append(items, page.Value...)
		next = page.NextLink
	}
	return items, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	fullURL, err := c.resolveURL(path)
	if err != nil {
		return nil, err
	}
	if c.tokenProvider == nil {
		return nil, fmt.Errorf("token provider is required")
	}
	tok, err := c.tokenProvider.AcquireToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	resp, err := c.httpClient.DoWithRedirectCheck(ctx, req, func(redirectReq *http.Request) error {
		if !c.isAuthorizedURL(redirectReq.URL) {
			return fmt.Errorf("graph redirect rejected: destination is outside the configured Graph origin")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graph returned status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *Client) resolveURL(path string) (string, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", fmt.Errorf("path is required")
	}
	base, err := url.Parse(c.baseURL)
	if err != nil || !validGraphURL(base) {
		return "", fmt.Errorf("configured Graph endpoint must be an HTTPS URL with a valid origin")
	}

	parsed, err := url.Parse(p)
	if err != nil {
		return "", fmt.Errorf("invalid Graph request URL")
	}
	var target *url.URL
	if parsed.IsAbs() || parsed.Host != "" {
		target = parsed
	} else {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		rel, parseErr := url.Parse(p)
		if parseErr != nil {
			return "", fmt.Errorf("invalid Graph request URL")
		}
		target = base.ResolveReference(rel)
	}
	if !validGraphURL(target) {
		return "", fmt.Errorf("Graph request URL must use HTTPS and the configured Graph origin")
	}
	if !sameOrigin(base, target) {
		return "", fmt.Errorf("Graph request URL is outside the configured Graph origin")
	}
	return target.String(), nil
}

func (c *Client) isAuthorizedURL(target *url.URL) bool {
	base, err := url.Parse(c.baseURL)
	return err == nil && validGraphURL(base) && validGraphURL(target) && sameOrigin(base, target)
}

func validGraphURL(u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, "https") && u.Hostname() != "" && !strings.HasSuffix(u.Host, ":") && u.User == nil && u.Opaque == "" && u.Fragment == "" && validPort(u)
}

func validPort(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		return true
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "443"
}
