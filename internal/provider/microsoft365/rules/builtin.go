package rules

import corerules "github.com/goldjg/stance/internal/core/rules"

func BuiltinRules() []corerules.Rule {
	out := make([]corerules.Rule, 0, len(BuiltinConditionalAccessRules())+len(BuiltinCollectionRules())+len(BuiltinDirectoryRoleRules()))
	out = append(out, BuiltinConditionalAccessRules()...)
	out = append(out, BuiltinCollectionRules()...)
	out = append(out, BuiltinDirectoryRoleRules()...)
	return out
}

func BuiltinConditionalAccessRules() []corerules.Rule {
	return []corerules.Rule{
		{
			ID:                  "ENTRA-CA-001",
			Title:               "Disabled Conditional Access policies are identified",
			Severity:            corerules.SeverityMedium,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All"},
			DataRequirements:    []string{"conditional_access_policies"},
			Remediation:         "Review disabled policies and either remove stale entries or re-enable required controls.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/overview"},
		},
		{
			ID:                  "ENTRA-CA-002",
			Title:               "Report-only Conditional Access policies are identified",
			Severity:            corerules.SeverityLow,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All"},
			DataRequirements:    []string{"conditional_access_policies"},
			Remediation:         "Review report-only policies and promote validated controls to enabled state.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only"},
		},
		{
			ID:                  "ENTRA-CA-003",
			Title:               "Conditional Access policies targeting privileged roles are identified",
			Severity:            corerules.SeverityMedium,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All"},
			DataRequirements:    []string{"conditional_access_policies"},
			Remediation:         "Ensure privileged-role-targeted policies are intentional, reviewed, and aligned to access strategy.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups"},
		},
		{
			ID:                  "ENTRA-CA-004",
			Title:               "Privileged-role Conditional Access policies enforce MFA or authentication strength",
			Severity:            corerules.SeverityHigh,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All"},
			DataRequirements:    []string{"conditional_access_policies"},
			Remediation:         "Add MFA grant control or authentication strength requirement to privileged-role-targeted policies.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength"},
		},
		{
			ID:                  "ENTRA-CA-005",
			Title:               "Privileged-role Conditional Access policies have user exclusions configured (informational)",
			Severity:            corerules.SeverityLow,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All"},
			DataRequirements:    []string{"conditional_access_policies"},
			Remediation:         "Review user exclusions and validate emergency-access intent out of band. Excluded users alone do not prove break-glass coverage.",
			References:          []string{"https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access"},
		},
		{
			ID:                  "ENTRA-CA-006",
			Title:               "Privileged principal Conditional Access coverage evidence is observed",
			Severity:            corerules.SeverityLow,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"},
			DataRequirements:    []string{"conditional_access_policies", "directory_role_assignments", "privileged_principals", "principal_group_memberships", "principal_group_resolutions"},
			Remediation:         "Use this evidence to prioritize follow-up validation. Observed coverage evidence is not complete effective-policy proof.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/overview"},
		},
		{
			ID:                  "ENTRA-CA-007",
			Title:               "Privileged principal Conditional Access exclusion evidence is observed",
			Severity:            corerules.SeverityLow,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"},
			DataRequirements:    []string{"conditional_access_policies", "directory_role_assignments", "privileged_principals", "principal_group_memberships", "principal_group_resolutions"},
			Remediation:         "Review direct and possible exclusion evidence. User exclusions alone do not prove emergency-access correctness.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups"},
		},
		{
			ID:                  "ENTRA-CA-008",
			Title:               "Privileged principal Conditional Access coverage remains unknown from current facts",
			Severity:            corerules.SeverityLow,
			Category:            "conditional-access",
			Service:             "entra",
			RequiredPermissions: []string{"Policy.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"},
			DataRequirements:    []string{"conditional_access_policies", "directory_role_assignments", "privileged_principals", "principal_group_memberships", "principal_group_resolutions"},
			Remediation:         "Expand fact collection and analysis scope for group resolution and effective-policy simulation before making coverage claims.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups"},
		},
	}
}

func BuiltinDirectoryRoleRules() []corerules.Rule {
	return []corerules.Rule{
		{
			ID:                  "ENTRA-ROLE-001",
			Title:               "Privileged directory role assignments are observed",
			Severity:            corerules.SeverityLow,
			Category:            "directory-role-assignments",
			Service:             "entra",
			RequiredPermissions: []string{"RoleManagement.Read.Directory"},
			DataRequirements:    []string{"directory_role_definitions", "directory_role_assignments", "privileged_principals"},
			Remediation:         "Use this visibility signal to validate privileged principal inventory and drive follow-up control review.",
			References:          []string{"https://learn.microsoft.com/graph/api/resources/unifiedroleassignment?view=graph-rest-1.0"},
		},
		{
			ID:                  "ENTRA-ROLE-002",
			Title:               "Privileged role assignments with incomplete principal details are observed",
			Severity:            corerules.SeverityLow,
			Category:            "directory-role-assignments",
			Service:             "entra",
			RequiredPermissions: []string{"RoleManagement.Read.Directory"},
			DataRequirements:    []string{"directory_role_assignments"},
			Remediation:         "Review principal detail resolution coverage; Directory.Read.All may be required for complete principal metadata in some tenants.",
			References:          []string{"https://learn.microsoft.com/graph/api/directoryobject-get?view=graph-rest-1.0"},
		},
	}
}

func BuiltinCollectionRules() []corerules.Rule {
	return []corerules.Rule{
		{
			ID:                  "ENTRA-COLLECT-001",
			Title:               "Microsoft 365 collection completeness evidence is observed",
			Severity:            corerules.SeverityLow,
			Category:            "collection-completeness",
			Service:             "entra",
			RequiredPermissions: []string{"Organization.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"},
			DataRequirements:    []string{"organization", "conditional_access_policies", "directory_role_definitions", "directory_role_assignments", "privileged_principals", "principal_group_memberships", "principal_group_resolutions"},
			Remediation:         "Use this readiness signal to identify collection gaps before drawing broad posture conclusions from current findings.",
			References:          []string{"https://learn.microsoft.com/entra/identity/conditional-access/overview"},
		},
	}
}
