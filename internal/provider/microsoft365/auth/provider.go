package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const assertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type TokenProvider interface {
	AcquireToken(ctx context.Context) (Token, error)
	Name() string
}

type tokenProvider struct {
	name       string
	httpClient *http.Client
	tokenURL   string
	values     url.Values
}

func NewTokenProvider(cfg Config) (TokenProvider, error) {
	values := url.Values{
		"client_id":  []string{cfg.ClientID},
		"scope":      []string{cfg.Scope},
		"grant_type": []string{"client_credentials"},
	}

	providerName := ""
	switch {
	case cfg.ClientSecret != "":
		providerName = "client_secret"
		values.Set("client_secret", cfg.ClientSecret)
	default:
		providerName = "workload_identity"
		assertion, err := readAssertion(cfg)
		if err != nil {
			return nil, err
		}
		values.Set("client_assertion_type", assertionTypeJWTBearer)
		values.Set("client_assertion", assertion)
	}

	return &tokenProvider{
		name:       providerName,
		httpClient: &http.Client{},
		tokenURL:   cfg.TokenURL,
		values:     values,
	}, nil
}

func (p *tokenProvider) Name() string {
	return p.name
}

func (p *tokenProvider) AcquireToken(ctx context.Context) (Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(p.values.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Token{}, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return Token{}, err
	}
	if tok.AccessToken == "" {
		return Token{}, errors.New("token response missing access_token")
	}
	return tok, nil
}

func readAssertion(cfg Config) (string, error) {
	if cfg.ClientAssertion != "" {
		return cfg.ClientAssertion, nil
	}
	raw, err := os.ReadFile(cfg.FederatedTokenFile)
	if err != nil {
		return "", err
	}
	assertion := strings.TrimSpace(string(raw))
	if assertion == "" {
		return "", errors.New("federated token file is empty")
	}
	return assertion, nil
}
