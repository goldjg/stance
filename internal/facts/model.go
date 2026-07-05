package facts

import "time"

type Bundle struct {
	CollectedAtUTC string             `json:"collected_at_utc"`
	Service        string             `json:"service"`
	Organization   []OrganizationFact `json:"organization"`
	CAPolicies     []CAPolicyFact     `json:"conditional_access_policies"`
}

func NewBundle() Bundle {
	return Bundle{
		CollectedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Service:        "microsoft-graph",
		Organization:   make([]OrganizationFact, 0),
		CAPolicies:     make([]CAPolicyFact, 0),
	}
}

type OrganizationFact struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	TenantType  string `json:"tenant_type,omitempty"`
}

type CAPolicyFact struct {
	ID                     string   `json:"id"`
	DisplayName            string   `json:"display_name"`
	State                  string   `json:"state"`
	IncludedUsers          []string `json:"included_users,omitempty"`
	ExcludedUsers          []string `json:"excluded_users,omitempty"`
	IncludedGroups         []string `json:"included_groups,omitempty"`
	ExcludedGroups         []string `json:"excluded_groups,omitempty"`
	IncludedRoles          []string `json:"included_roles,omitempty"`
	ExcludedRoles          []string `json:"excluded_roles,omitempty"`
	BuiltInControls        []string `json:"built_in_controls,omitempty"`
	AuthenticationStrength string   `json:"authentication_strength,omitempty"`
}
