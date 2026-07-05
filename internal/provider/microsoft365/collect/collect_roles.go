package collect

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

const roleDefinitionsPath = "/v1.0/roleManagement/directory/roleDefinitions?$top=100"
const roleAssignmentsPath = "/v1.0/roleManagement/directory/roleAssignments?$top=100"

type DirectoryRoleCollector struct{}

func (DirectoryRoleCollector) Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error {
	definitions, err := collectDirectoryRoleDefinitions(ctx, client)
	if err != nil {
		return err
	}
	bundle.DirectoryRoleDefinitions = append(bundle.DirectoryRoleDefinitions, definitions...)

	byID := make(map[string]facts.DirectoryRoleDefinition, len(definitions))
	for _, definition := range definitions {
		byID[definition.ID] = definition
	}

	assignments, err := collectDirectoryRoleAssignments(ctx, client, byID)
	if err != nil {
		return err
	}
	bundle.DirectoryRoleAssignments = append(bundle.DirectoryRoleAssignments, assignments...)
	bundle.PrivilegedPrincipals = append(bundle.PrivilegedPrincipals, derivePrivilegedPrincipals(assignments)...)
	return nil
}

func collectDirectoryRoleDefinitions(ctx context.Context, client *graph.Client) ([]facts.DirectoryRoleDefinition, error) {
	rawItems, err := client.CollectPaginated(ctx, roleDefinitionsPath)
	if err != nil {
		return nil, err
	}
	out := make([]facts.DirectoryRoleDefinition, 0, len(rawItems))
	for _, raw := range rawItems {
		definition, mapErr := mapDirectoryRoleDefinition(raw)
		if mapErr != nil {
			return nil, mapErr
		}
		out = append(out, definition)
	}
	return out, nil
}

func collectDirectoryRoleAssignments(ctx context.Context, client *graph.Client, roleByID map[string]facts.DirectoryRoleDefinition) ([]facts.DirectoryRoleAssignment, error) {
	rawItems, err := client.CollectPaginated(ctx, roleAssignmentsPath)
	if err != nil {
		return nil, err
	}
	principalByID := make(map[string]principalDetail)
	out := make([]facts.DirectoryRoleAssignment, 0, len(rawItems))
	for _, raw := range rawItems {
		assignment, mapErr := mapDirectoryRoleAssignment(raw)
		if mapErr != nil {
			return nil, mapErr
		}
		if role, ok := roleByID[assignment.RoleDefinitionID]; ok && role.DisplayName != "" {
			assignment.RoleDisplayName = role.DisplayName
		}

		detail := principalByID[assignment.PrincipalID]
		if detail.PrincipalID == "" && strings.TrimSpace(assignment.PrincipalID) != "" {
			lookedUp, lookupErr := lookupPrincipalDetail(ctx, client, assignment.PrincipalID)
			if lookupErr == nil {
				detail = lookedUp
			} else {
				detail = principalDetail{
					PrincipalID: assignment.PrincipalID,
					Found:       false,
				}
			}
			principalByID[assignment.PrincipalID] = detail
		}
		if detail.Found {
			if detail.PrincipalType != "" {
				assignment.PrincipalType = detail.PrincipalType
			}
			if detail.DisplayName != "" {
				assignment.PrincipalDisplayName = detail.DisplayName
			}
			if detail.UserPrincipalName != "" {
				assignment.PrincipalUserPrincipalName = detail.UserPrincipalName
			}
		}
		out = append(out, assignment)
	}
	return out, nil
}

func mapDirectoryRoleDefinition(raw json.RawMessage) (facts.DirectoryRoleDefinition, error) {
	var payload struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
		IsBuiltIn   *bool  `json:"isBuiltIn"`
		TemplateID  string `json:"templateId"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return facts.DirectoryRoleDefinition{}, err
	}
	return facts.DirectoryRoleDefinition{
		ID:          payload.ID,
		DisplayName: payload.DisplayName,
		Description: payload.Description,
		IsBuiltIn:   payload.IsBuiltIn,
		TemplateID:  payload.TemplateID,
	}, nil
}

func mapDirectoryRoleAssignment(raw json.RawMessage) (facts.DirectoryRoleAssignment, error) {
	var payload struct {
		ID               string `json:"id"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		AssignmentType   string `json:"assignmentType"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return facts.DirectoryRoleAssignment{}, err
	}
	return facts.DirectoryRoleAssignment{
		ID:               payload.ID,
		RoleDefinitionID: payload.RoleDefinitionID,
		PrincipalID:      payload.PrincipalID,
		PrincipalType:    strings.TrimSpace(payload.PrincipalType),
		AssignmentType:   strings.TrimSpace(payload.AssignmentType),
		Source:           "graph:/v1.0/roleManagement/directory/roleAssignments",
	}, nil
}

type principalDetail struct {
	PrincipalID       string
	PrincipalType     string
	DisplayName       string
	UserPrincipalName string
	Found             bool
}

func lookupPrincipalDetail(ctx context.Context, client *graph.Client, principalID string) (principalDetail, error) {
	var payload struct {
		ID                string `json:"id"`
		ODataType         string `json:"@odata.type"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	path := "/v1.0/directoryObjects/" + principalID + "?$select=id,displayName,userPrincipalName"
	if err := client.GetJSON(ctx, path, &payload); err != nil {
		return principalDetail{}, err
	}
	return principalDetail{
		PrincipalID:       payload.ID,
		PrincipalType:     normalizePrincipalType(payload.ODataType),
		DisplayName:       payload.DisplayName,
		UserPrincipalName: payload.UserPrincipalName,
		Found:             true,
	}, nil
}

func normalizePrincipalType(odataType string) string {
	v := strings.TrimSpace(odataType)
	v = strings.TrimPrefix(v, "#microsoft.graph.")
	return v
}

func derivePrivilegedPrincipals(assignments []facts.DirectoryRoleAssignment) []facts.PrivilegedPrincipal {
	type aggregate struct {
		principalID       string
		principalType     string
		displayName       string
		userPrincipalName string
		roleIDs           map[string]struct{}
		roleNames         map[string]struct{}
	}
	aggByPrincipal := make(map[string]*aggregate)
	for _, assignment := range assignments {
		id := strings.TrimSpace(assignment.PrincipalID)
		if id == "" {
			continue
		}
		agg := aggByPrincipal[id]
		if agg == nil {
			agg = &aggregate{
				principalID: id,
				roleIDs:     make(map[string]struct{}),
				roleNames:   make(map[string]struct{}),
			}
			aggByPrincipal[id] = agg
		}
		if agg.principalType == "" && assignment.PrincipalType != "" {
			agg.principalType = assignment.PrincipalType
		}
		if agg.displayName == "" && assignment.PrincipalDisplayName != "" {
			agg.displayName = assignment.PrincipalDisplayName
		}
		if agg.userPrincipalName == "" && assignment.PrincipalUserPrincipalName != "" {
			agg.userPrincipalName = assignment.PrincipalUserPrincipalName
		}
		if assignment.RoleDefinitionID != "" {
			agg.roleIDs[assignment.RoleDefinitionID] = struct{}{}
		}
		if assignment.RoleDisplayName != "" {
			agg.roleNames[assignment.RoleDisplayName] = struct{}{}
		}
	}

	out := make([]facts.PrivilegedPrincipal, 0, len(aggByPrincipal))
	for _, agg := range aggByPrincipal {
		roleIDs := make([]string, 0, len(agg.roleIDs))
		for roleID := range agg.roleIDs {
			roleIDs = append(roleIDs, roleID)
		}
		sort.Strings(roleIDs)

		roleNames := make([]string, 0, len(agg.roleNames))
		for roleName := range agg.roleNames {
			roleNames = append(roleNames, roleName)
		}
		sort.Strings(roleNames)

		out = append(out, facts.PrivilegedPrincipal{
			PrincipalID:       agg.principalID,
			PrincipalType:     agg.principalType,
			DisplayName:       agg.displayName,
			UserPrincipalName: agg.userPrincipalName,
			RoleDefinitionIDs: roleIDs,
			RoleDisplayNames:  roleNames,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PrincipalID < out[j].PrincipalID
	})
	return out
}
