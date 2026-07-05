package facts

import (
	"encoding/json"
	"time"
)

type Bundle struct {
	CollectedAtUTC           string                    `json:"collected_at_utc"`
	Service                  string                    `json:"service"`
	Organization             []OrganizationFact        `json:"organization"`
	CAPolicies               []CAPolicyFact            `json:"conditional_access_policies"`
	DirectoryRoleDefinitions []DirectoryRoleDefinition `json:"directory_role_definitions"`
	DirectoryRoleAssignments []DirectoryRoleAssignment `json:"directory_role_assignments"`
	PrivilegedPrincipals     []PrivilegedPrincipal     `json:"privileged_principals"`
}

func NewBundle() Bundle {
	b := Bundle{
		CollectedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Service:        "microsoft-graph",
	}
	b.ensureDefaults()
	return b
}

func (b *Bundle) UnmarshalJSON(data []byte) error {
	type alias Bundle
	var raw alias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*b = Bundle(raw)
	b.ensureDefaults()
	return nil
}

func (b *Bundle) ensureDefaults() {
	if b.Organization == nil {
		b.Organization = make([]OrganizationFact, 0)
	}
	if b.CAPolicies == nil {
		b.CAPolicies = make([]CAPolicyFact, 0)
	}
	if b.DirectoryRoleDefinitions == nil {
		b.DirectoryRoleDefinitions = make([]DirectoryRoleDefinition, 0)
	}
	if b.DirectoryRoleAssignments == nil {
		b.DirectoryRoleAssignments = make([]DirectoryRoleAssignment, 0)
	}
	if b.PrivilegedPrincipals == nil {
		b.PrivilegedPrincipals = make([]PrivilegedPrincipal, 0)
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

type DirectoryRoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	IsBuiltIn   *bool  `json:"is_built_in,omitempty"`
	TemplateID  string `json:"template_id,omitempty"`
}

type DirectoryRoleAssignment struct {
	ID                         string `json:"id"`
	RoleDefinitionID           string `json:"role_definition_id"`
	RoleDisplayName            string `json:"role_display_name,omitempty"`
	PrincipalID                string `json:"principal_id"`
	PrincipalType              string `json:"principal_type,omitempty"`
	PrincipalDisplayName       string `json:"principal_display_name,omitempty"`
	PrincipalUserPrincipalName string `json:"principal_user_principal_name,omitempty"`
	AssignmentType             string `json:"assignment_type,omitempty"`
	Source                     string `json:"source"`
}

type PrivilegedPrincipal struct {
	PrincipalID       string   `json:"principal_id"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	DisplayName       string   `json:"display_name,omitempty"`
	UserPrincipalName string   `json:"user_principal_name,omitempty"`
	RoleDefinitionIDs []string `json:"role_definition_ids"`
	RoleDisplayNames  []string `json:"role_display_names"`
}
