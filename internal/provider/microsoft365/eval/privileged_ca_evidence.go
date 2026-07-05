package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

type PrivilegedPrincipalCAEvidence struct {
	PrincipalID                  string   `json:"principal_id"`
	PrincipalType                string   `json:"principal_type,omitempty"`
	DisplayName                  string   `json:"display_name,omitempty"`
	UserPrincipalName            string   `json:"user_principal_name,omitempty"`
	RoleDisplayNames             []string `json:"role_display_names"`
	DirectGroupIDs               []string `json:"direct_group_ids"`
	DirectGroupDisplayNames      []string `json:"direct_group_display_names"`
	ObservedCoveringPolicyIDs    []string `json:"observed_covering_policy_ids"`
	ObservedCoveringPolicyNames  []string `json:"observed_covering_policy_names"`
	ObservedExcludingPolicyIDs   []string `json:"observed_excluding_policy_ids"`
	ObservedExcludingPolicyNames []string `json:"observed_excluding_policy_names"`
	CoverageEvidence             []string `json:"coverage_evidence"`
	ExclusionEvidence            []string `json:"exclusion_evidence"`
	Limitations                  []string `json:"limitations"`
}

type PrivilegedCAEvidenceSummary struct {
	Principals                              []PrivilegedPrincipalCAEvidence `json:"principals"`
	TotalPrivilegedPrincipals               int                             `json:"total_privileged_principals"`
	PrincipalsWithCoverageEvidence          int                             `json:"principals_with_coverage_evidence"`
	PrincipalsWithDirectExclusionEvidence   int                             `json:"principals_with_direct_exclusion_evidence"`
	PrincipalsWithPossibleExclusionEvidence int                             `json:"principals_with_possible_exclusion_evidence"`
	PrincipalsWithUnknownCoverage           int                             `json:"principals_with_unknown_coverage"`
}

func DerivePrivilegedCAEvidence(bundle facts.Bundle) PrivilegedCAEvidenceSummary {
	byPrincipalID := make(map[string][]facts.DirectoryRoleAssignment)
	for _, assignment := range bundle.DirectoryRoleAssignments {
		id := strings.TrimSpace(assignment.PrincipalID)
		if id == "" {
			continue
		}
		byPrincipalID[id] = append(byPrincipalID[id], assignment)
	}
	groupsByPrincipalID := make(map[string][]facts.PrincipalGroupMembership)
	for _, membership := range bundle.PrincipalGroupMemberships {
		id := strings.TrimSpace(membership.PrincipalID)
		if id == "" {
			continue
		}
		groupsByPrincipalID[id] = append(groupsByPrincipalID[id], membership)
	}

	principals := append([]facts.PrivilegedPrincipal(nil), bundle.PrivilegedPrincipals...)
	sort.Slice(principals, func(i, j int) bool {
		return principals[i].PrincipalID < principals[j].PrincipalID
	})

	out := make([]PrivilegedPrincipalCAEvidence, 0, len(principals))
	summary := PrivilegedCAEvidenceSummary{
		TotalPrivilegedPrincipals: len(principals),
	}

	for _, principal := range principals {
		assignments := byPrincipalID[strings.TrimSpace(principal.PrincipalID)]
		roleIDs := mergeRoleIDs(principal.RoleDefinitionIDs, assignments)
		roleNames := mergeRoleNames(principal.RoleDisplayNames, assignments)
		principalGroups := groupsByPrincipalID[strings.TrimSpace(principal.PrincipalID)]
		directGroupIDs := mergeDirectGroupIDs(principalGroups)
		directGroupNames := mergeDirectGroupNames(principalGroups)

		evidence := PrivilegedPrincipalCAEvidence{
			PrincipalID:             principal.PrincipalID,
			PrincipalType:           principal.PrincipalType,
			DisplayName:             principal.DisplayName,
			UserPrincipalName:       principal.UserPrincipalName,
			RoleDisplayNames:        roleNames,
			DirectGroupIDs:          directGroupIDs,
			DirectGroupDisplayNames: directGroupNames,
			Limitations:             defaultPrivilegedCALimitations(),
		}

		coveringIDs := make(map[string]struct{})
		coveringNames := make(map[string]struct{})
		excludingIDs := make(map[string]struct{})
		excludingNames := make(map[string]struct{})

		hasDirectExclusion := false
		hasPossibleExclusion := false

		for _, policy := range bundle.CAPolicies {
			if strings.TrimSpace(policy.State) != "enabled" {
				continue
			}
			if !hasMFAControl(policy) {
				continue
			}

			roleTargeted := intersects(policy.IncludedRoles, roleIDs)
			allUsersTargeted := includesAllUsers(policy.IncludedUsers)
			principalIncluded := principalMatch(policy.IncludedUsers, principal.PrincipalID, principal.UserPrincipalName)
			groupIncluded := intersects(policy.IncludedGroups, directGroupIDs)
			targeted := roleTargeted || allUsersTargeted || principalIncluded || groupIncluded
			if !targeted {
				continue
			}

			policyID := strings.TrimSpace(policy.ID)
			policyName := strings.TrimSpace(policy.DisplayName)
			if policyName == "" {
				policyName = policyID
			}

			coveringIDs[policyID] = struct{}{}
			coveringNames[policyName] = struct{}{}
			if principalIncluded {
				evidence.CoverageEvidence = append(evidence.CoverageEvidence, fmt.Sprintf("Direct principal evidence: enabled policy %q with MFA/authentication-strength grant control directly includes this principal.", policyName))
			}
			if groupIncluded {
				evidence.CoverageEvidence = append(evidence.CoverageEvidence, fmt.Sprintf("Direct group membership evidence: enabled policy %q with MFA/authentication-strength grant control includes a group this principal is directly a member of.", policyName))
			}
			if roleTargeted {
				evidence.CoverageEvidence = append(evidence.CoverageEvidence, fmt.Sprintf("Role-target evidence: enabled policy %q with MFA/authentication-strength grant control includes one or more directory roles assigned to this privileged principal.", policyName))
			}
			if allUsersTargeted {
				evidence.CoverageEvidence = append(evidence.CoverageEvidence, fmt.Sprintf("All-users evidence: enabled policy %q with MFA/authentication-strength grant control targets all users.", policyName))
			}

			principalExcluded := principalMatch(policy.ExcludedUsers, principal.PrincipalID, principal.UserPrincipalName)
			groupExcluded := intersects(policy.ExcludedGroups, directGroupIDs)
			if principalExcluded || groupExcluded {
				hasDirectExclusion = true
				excludingIDs[policyID] = struct{}{}
				excludingNames[policyName] = struct{}{}
				if principalExcluded {
					evidence.ExclusionEvidence = append(evidence.ExclusionEvidence, fmt.Sprintf("Direct principal exclusion evidence: policy %q excludes this principal by explicit user identifier.", policyName))
				}
				if groupExcluded {
					evidence.ExclusionEvidence = append(evidence.ExclusionEvidence, fmt.Sprintf("Direct group membership exclusion evidence: policy %q excludes a group this principal is directly a member of.", policyName))
				}
				continue
			}

			if len(policy.ExcludedUsers) > 0 {
				hasPossibleExclusion = true
				excludingIDs[policyID] = struct{}{}
				excludingNames[policyName] = struct{}{}
				evidence.ExclusionEvidence = append(evidence.ExclusionEvidence, fmt.Sprintf("Possible-only exclusion evidence: policy %q targets this principal context and excludes one or more users, but no direct principal-level or direct group-level exclusion proof was observed from current facts.", policyName))
			}
		}

		evidence.ObservedCoveringPolicyIDs = sortedKeys(coveringIDs)
		evidence.ObservedCoveringPolicyNames = sortedKeys(coveringNames)
		evidence.ObservedExcludingPolicyIDs = sortedKeys(excludingIDs)
		evidence.ObservedExcludingPolicyNames = sortedKeys(excludingNames)
		sort.Strings(evidence.CoverageEvidence)
		sort.Strings(evidence.ExclusionEvidence)

		if len(evidence.ObservedCoveringPolicyIDs) > 0 {
			summary.PrincipalsWithCoverageEvidence++
		} else {
			summary.PrincipalsWithUnknownCoverage++
		}
		if hasDirectExclusion {
			summary.PrincipalsWithDirectExclusionEvidence++
		}
		if hasPossibleExclusion {
			summary.PrincipalsWithPossibleExclusionEvidence++
		}

		out = append(out, evidence)
	}

	summary.Principals = out
	return summary
}

func normalizePrivilegedCAEvidenceSummary(summary PrivilegedCAEvidenceSummary) PrivilegedCAEvidenceSummary {
	out := summary
	out.Principals = append([]PrivilegedPrincipalCAEvidence(nil), summary.Principals...)
	sort.Slice(out.Principals, func(i, j int) bool {
		return out.Principals[i].PrincipalID < out.Principals[j].PrincipalID
	})
	for i := range out.Principals {
		principal := &out.Principals[i]
		principal.RoleDisplayNames = sortedStrings(principal.RoleDisplayNames)
		principal.DirectGroupIDs = sortedStrings(principal.DirectGroupIDs)
		principal.DirectGroupDisplayNames = sortedStrings(principal.DirectGroupDisplayNames)
		principal.ObservedCoveringPolicyIDs = sortedStrings(principal.ObservedCoveringPolicyIDs)
		principal.ObservedCoveringPolicyNames = sortedStrings(principal.ObservedCoveringPolicyNames)
		principal.ObservedExcludingPolicyIDs = sortedStrings(principal.ObservedExcludingPolicyIDs)
		principal.ObservedExcludingPolicyNames = sortedStrings(principal.ObservedExcludingPolicyNames)
		principal.CoverageEvidence = sortedStrings(principal.CoverageEvidence)
		principal.ExclusionEvidence = sortedStrings(principal.ExclusionEvidence)
		principal.Limitations = sortedStrings(principal.Limitations)
	}
	return out
}

func mergeDirectGroupIDs(memberships []facts.PrincipalGroupMembership) []string {
	set := make(map[string]struct{})
	for _, membership := range memberships {
		groupID := strings.TrimSpace(membership.GroupID)
		if groupID == "" {
			continue
		}
		set[groupID] = struct{}{}
	}
	return sortedKeys(set)
}

func mergeDirectGroupNames(memberships []facts.PrincipalGroupMembership) []string {
	set := make(map[string]struct{})
	for _, membership := range memberships {
		name := strings.TrimSpace(membership.GroupDisplayName)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	return sortedKeys(set)
}

func mergeRoleIDs(roleIDs []string, assignments []facts.DirectoryRoleAssignment) []string {
	set := make(map[string]struct{})
	for _, roleID := range roleIDs {
		if strings.TrimSpace(roleID) == "" {
			continue
		}
		set[strings.TrimSpace(roleID)] = struct{}{}
	}
	for _, assignment := range assignments {
		if strings.TrimSpace(assignment.RoleDefinitionID) == "" {
			continue
		}
		set[strings.TrimSpace(assignment.RoleDefinitionID)] = struct{}{}
	}
	return sortedKeys(set)
}

func mergeRoleNames(roleNames []string, assignments []facts.DirectoryRoleAssignment) []string {
	set := make(map[string]struct{})
	for _, roleName := range roleNames {
		if strings.TrimSpace(roleName) == "" {
			continue
		}
		set[strings.TrimSpace(roleName)] = struct{}{}
	}
	for _, assignment := range assignments {
		if strings.TrimSpace(assignment.RoleDisplayName) == "" {
			continue
		}
		set[strings.TrimSpace(assignment.RoleDisplayName)] = struct{}{}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func includesAllUsers(includedUsers []string) bool {
	for _, value := range includedUsers {
		if strings.EqualFold(strings.TrimSpace(value), "all") {
			return true
		}
	}
	return false
}

func principalMatch(values []string, principalID, principalUPN string) bool {
	id := strings.TrimSpace(principalID)
	upn := strings.TrimSpace(principalUPN)
	for _, value := range values {
		candidate := strings.TrimSpace(value)
		if candidate == "" {
			continue
		}
		if id != "" && strings.EqualFold(candidate, id) {
			return true
		}
		if upn != "" && strings.EqualFold(candidate, upn) {
			return true
		}
	}
	return false
}

func intersects(a []string, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	lookup := make(map[string]struct{}, len(b))
	for _, item := range b {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		lookup[strings.ToLower(v)] = struct{}{}
	}
	for _, item := range a {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := lookup[strings.ToLower(v)]; ok {
			return true
		}
	}
	return false
}

func defaultPrivilegedCALimitations() []string {
	return []string{
		"Nested and transitive group expansion is not implemented in this release.",
		"Dynamic group rule evaluation is not implemented in this release.",
		"Emergency-access or break-glass account designation is not known from current facts.",
		"Full effective Conditional Access policy simulation is not implemented in this release.",
		"Conditional Access conditions (for example app, platform, client app, location, or risk) can materially change effective coverage.",
		"Report-only policies are intentionally excluded from enforcement evidence.",
	}
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
