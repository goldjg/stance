package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goldjg/stance-365/internal/auth"
	"github.com/goldjg/stance-365/internal/httpclient"
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
	if c.tokenProvider == nil {
		return nil, fmt.Errorf("token provider is required")
	}
	tok, err := c.tokenProvider.AcquireToken(ctx)
	if err != nil {
		return nil, err
	}

	fullURL, err := c.resolveURL(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	resp, err := c.httpClient.Do(ctx, req)
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
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p, nil
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	rel, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}
