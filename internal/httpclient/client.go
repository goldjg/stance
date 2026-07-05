package httpclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxRetries = 3
	defaultTimeout    = 30 * time.Second
)

type Client struct {
	httpClient *http.Client
	maxRetries int
	userAgent  string
}

func New(userAgent string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		maxRetries: defaultMaxRetries,
		userAgent:  strings.TrimSpace(userAgent),
	}
}

func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	if hc != nil {
		c.httpClient = hc
	}
	return c
}

func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		r := req.Clone(ctx)
		if c.userAgent != "" && r.Header.Get("User-Agent") == "" {
			r.Header.Set("User-Agent", c.userAgent)
		}

		resp, err = c.httpClient.Do(r)
		if err != nil {
			if attempt == c.maxRetries {
				return nil, err
			}
			waitForRetry(ctx, fallbackWait(attempt))
			continue
		}

		if !shouldRetryStatus(resp.StatusCode) || attempt == c.maxRetries {
			return resp, nil
		}

		wait := retryAfterDuration(resp.Header.Get("Retry-After"), attempt)
		_ = resp.Body.Close()
		waitForRetry(ctx, wait)
	}

	return nil, fmt.Errorf("request retries exhausted")
}

func shouldRetryStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}

func retryAfterDuration(v string, attempt int) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallbackWait(attempt)
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return fallbackWait(attempt)
		}
		return time.Duration(secs) * time.Second
	}
	if ts, err := http.ParseTime(v); err == nil {
		wait := time.Until(ts)
		if wait < 0 {
			return 0
		}
		return wait
	}
	return fallbackWait(attempt)
}

func fallbackWait(attempt int) time.Duration {
	// 100ms, 200ms, 400ms, 800ms ...
	ms := 100 * math.Pow(2, float64(attempt))
	return time.Duration(ms) * time.Millisecond
}

func waitForRetry(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
