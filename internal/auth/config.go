package auth

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	defaultScope = "https://graph.microsoft.com/.default"
)

type Config struct {
	TenantID           string
	ClientID           string
	TokenURL           string
	Scope              string
	ClientSecret       string
	ClientAssertion    string
	FederatedTokenFile string
}

func ConfigFromEnv() (Config, error) {
	cfg := Config{
		TenantID:           strings.TrimSpace(os.Getenv("STANCE_TENANT_ID")),
		ClientID:           strings.TrimSpace(os.Getenv("STANCE_CLIENT_ID")),
		TokenURL:           strings.TrimSpace(os.Getenv("STANCE_TOKEN_URL")),
		Scope:              strings.TrimSpace(os.Getenv("STANCE_SCOPE")),
		ClientSecret:       strings.TrimSpace(os.Getenv("STANCE_CLIENT_SECRET")),
		ClientAssertion:    strings.TrimSpace(os.Getenv("STANCE_CLIENT_ASSERTION")),
		FederatedTokenFile: strings.TrimSpace(os.Getenv("STANCE_FEDERATED_TOKEN_FILE")),
	}
	if cfg.Scope == "" {
		cfg.Scope = defaultScope
	}
	if cfg.TenantID == "" {
		return Config{}, errors.New("STANCE_TENANT_ID is required")
	}
	if cfg.ClientID == "" {
		return Config{}, errors.New("STANCE_CLIENT_ID is required")
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
	}
	if cfg.ClientSecret != "" && (cfg.ClientAssertion != "" || cfg.FederatedTokenFile != "") {
		return Config{}, errors.New("ambiguous auth config: set either client secret or workload identity assertion, not both")
	}
	if cfg.ClientAssertion != "" && cfg.FederatedTokenFile != "" {
		return Config{}, errors.New("ambiguous auth config: set either STANCE_CLIENT_ASSERTION or STANCE_FEDERATED_TOKEN_FILE, not both")
	}
	if cfg.ClientSecret == "" && cfg.ClientAssertion == "" && cfg.FederatedTokenFile == "" {
		return Config{}, errors.New("no auth material provided: set STANCE_CLIENT_SECRET or STANCE_CLIENT_ASSERTION or STANCE_FEDERATED_TOKEN_FILE")
	}
	return cfg, nil
}
