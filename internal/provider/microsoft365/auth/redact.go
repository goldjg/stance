package auth

import "regexp"

var secretPattern = regexp.MustCompile(`(?i)(client_secret=|client_assertion=|access_token["=: ]+)([^&\s",]+)`)

func Redact(input string) string {
	return secretPattern.ReplaceAllString(input, "${1}[REDACTED]")
}

func RedactTenantID(tenantID string) string {
	if len(tenantID) <= 8 {
		return "[REDACTED]"
	}
	return tenantID[:4] + "..." + tenantID[len(tenantID)-4:]
}
