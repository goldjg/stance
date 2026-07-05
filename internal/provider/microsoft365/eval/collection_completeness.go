package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
)

type CollectionCompletenessSummary struct {
	ConditionalAccessPolicyCount   int      `json:"conditional_access_policy_count"`
	DirectoryRoleDefinitionCount   int      `json:"directory_role_definition_count"`
	DirectoryRoleAssignmentCount   int      `json:"directory_role_assignment_count"`
	PrivilegedPrincipalCount       int      `json:"privileged_principal_count"`
	PrincipalGroupMembershipCount  int      `json:"principal_group_membership_count"`
	PrincipalGroupResolutionCount  int      `json:"principal_group_resolution_count"`
	UnresolvedGroupResolutionCount int      `json:"unresolved_group_resolution_count"`
	MissingGroupResolutionCount    int      `json:"missing_group_resolution_count"`
	CompletenessStatus             string   `json:"completeness_status"`
	Limitations                    []string `json:"limitations"`
}

func DeriveCollectionCompletenessSummary(bundle facts.Bundle) CollectionCompletenessSummary {
	summary := CollectionCompletenessSummary{
		ConditionalAccessPolicyCount:  len(bundle.CAPolicies),
		DirectoryRoleDefinitionCount:  len(bundle.DirectoryRoleDefinitions),
		DirectoryRoleAssignmentCount:  len(bundle.DirectoryRoleAssignments),
		PrivilegedPrincipalCount:      len(bundle.PrivilegedPrincipals),
		PrincipalGroupMembershipCount: len(bundle.PrincipalGroupMemberships),
		PrincipalGroupResolutionCount: len(bundle.PrincipalGroupResolutions),
		CompletenessStatus:            "complete_for_current_scope",
		Limitations: []string{
			"Collection completeness is readiness evidence for currently implemented Entra checks, not a tenant score or safety determination.",
		},
	}

	resolutionByPrincipalID := make(map[string]facts.PrincipalGroupResolution)
	for _, resolution := range bundle.PrincipalGroupResolutions {
		principalID := strings.TrimSpace(resolution.PrincipalID)
		if principalID == "" {
			continue
		}
		if _, exists := resolutionByPrincipalID[principalID]; exists {
			continue
		}
		resolutionByPrincipalID[principalID] = resolution
	}

	privilegedIDs := make(map[string]struct{})
	for _, principal := range bundle.PrivilegedPrincipals {
		principalID := strings.TrimSpace(principal.PrincipalID)
		if principalID == "" {
			continue
		}
		privilegedIDs[principalID] = struct{}{}
	}
	for principalID := range privilegedIDs {
		resolution, found := resolutionByPrincipalID[principalID]
		if !found {
			summary.MissingGroupResolutionCount++
			continue
		}
		if !resolution.Resolved {
			summary.UnresolvedGroupResolutionCount++
		}
	}

	if summary.DirectoryRoleAssignmentCount == 0 {
		summary.CompletenessStatus = "unknown"
		summary.Limitations = append(summary.Limitations, "Directory role assignment facts are missing; current facts contain no privileged role assignment evidence.")
	}
	if summary.ConditionalAccessPolicyCount == 0 {
		summary.CompletenessStatus = "partial"
		summary.Limitations = append(summary.Limitations, "Conditional Access policy facts are missing.")
	}
	if summary.DirectoryRoleAssignmentCount > 0 && summary.PrivilegedPrincipalCount == 0 {
		summary.CompletenessStatus = "partial"
		summary.Limitations = append(summary.Limitations, "Directory role assignments were collected but no privileged principals were derived from current facts.")
	}
	if summary.UnresolvedGroupResolutionCount > 0 {
		summary.CompletenessStatus = "partial"
		summary.Limitations = append(summary.Limitations, fmt.Sprintf("%d privileged principals have failed direct group resolution.", summary.UnresolvedGroupResolutionCount))
	}
	if summary.MissingGroupResolutionCount > 0 {
		summary.CompletenessStatus = "partial"
		summary.Limitations = append(summary.Limitations, fmt.Sprintf("%d privileged principals have unknown direct group resolution status.", summary.MissingGroupResolutionCount))
	}

	summary.Limitations = uniqueSorted(summary.Limitations)
	return summary
}

func summarizeCollectionCompleteness(summary CollectionCompletenessSummary) string {
	switch summary.CompletenessStatus {
	case "complete_for_current_scope":
		return "Collection appears complete for current implemented Entra evidence scope. This is readiness evidence only, not a tenant safety claim."
	case "partial":
		return "Collection is partial for current implemented Entra evidence scope; findings may be based on incomplete evidence."
	default:
		return "Collection completeness is unknown for current implemented Entra evidence scope; current facts do not include privileged role assignment evidence."
	}
}

func matchedCollectionCompletenessGaps(summary CollectionCompletenessSummary) []string {
	out := make([]string, 0)
	if summary.UnresolvedGroupResolutionCount > 0 {
		out = append(out, fmt.Sprintf("%d privileged principals have failed direct group resolution", summary.UnresolvedGroupResolutionCount))
	}
	if summary.MissingGroupResolutionCount > 0 {
		out = append(out, fmt.Sprintf("%d privileged principals have unknown direct group resolution status", summary.MissingGroupResolutionCount))
	}
	if summary.ConditionalAccessPolicyCount == 0 {
		out = append(out, "Conditional Access policy facts are missing")
	}
	if summary.DirectoryRoleAssignmentCount == 0 {
		out = append(out, "Directory role assignment facts are missing; current facts contain no privileged role assignment evidence")
	}
	if summary.DirectoryRoleAssignmentCount > 0 && summary.PrivilegedPrincipalCount == 0 {
		out = append(out, "Directory role assignments were collected but no privileged principals were derived")
	}
	sort.Strings(out)
	return out
}

func collectionCompletenessDetails(summary CollectionCompletenessSummary) map[string]any {
	return map[string]any{
		"collection_completeness": map[string]any{
			"conditional_access_policy_count":   summary.ConditionalAccessPolicyCount,
			"directory_role_definition_count":   summary.DirectoryRoleDefinitionCount,
			"directory_role_assignment_count":   summary.DirectoryRoleAssignmentCount,
			"privileged_principal_count":        summary.PrivilegedPrincipalCount,
			"principal_group_membership_count":  summary.PrincipalGroupMembershipCount,
			"principal_group_resolution_count":  summary.PrincipalGroupResolutionCount,
			"unresolved_group_resolution_count": summary.UnresolvedGroupResolutionCount,
			"missing_group_resolution_count":    summary.MissingGroupResolutionCount,
			"completeness_status":               summary.CompletenessStatus,
			"limitations":                       append([]string(nil), summary.Limitations...),
		},
	}
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
