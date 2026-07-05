package collect

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

type PrivilegedPrincipalGroupMembershipCollector struct{}

func (PrivilegedPrincipalGroupMembershipCollector) Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error {
	seen := make(map[string]struct{})
	collected := make([]facts.PrincipalGroupMembership, 0)

	for _, principal := range bundle.PrivilegedPrincipals {
		principalID := strings.TrimSpace(principal.PrincipalID)
		if principalID == "" {
			continue
		}
		items, err := collectDirectGroupMembershipsForPrincipal(ctx, client, principal)
		if err != nil {
			continue
		}
		for _, item := range items {
			key := principalID + "|" + strings.TrimSpace(item.GroupID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			collected = append(collected, item)
		}
	}

	sort.Slice(collected, func(i, j int) bool {
		if collected[i].PrincipalID != collected[j].PrincipalID {
			return collected[i].PrincipalID < collected[j].PrincipalID
		}
		return collected[i].GroupID < collected[j].GroupID
	})
	bundle.PrincipalGroupMemberships = append(bundle.PrincipalGroupMemberships, collected...)
	return nil
}

func collectDirectGroupMembershipsForPrincipal(ctx context.Context, client *graph.Client, principal facts.PrivilegedPrincipal) ([]facts.PrincipalGroupMembership, error) {
	principalID := strings.TrimSpace(principal.PrincipalID)
	if principalID == "" {
		return nil, nil
	}
	path := "/v1.0/directoryObjects/" + url.PathEscape(principalID) + "/memberOf?$select=id,displayName"
	rawItems, err := client.CollectPaginated(ctx, path)
	if err != nil {
		return nil, err
	}

	out := make([]facts.PrincipalGroupMembership, 0, len(rawItems))
	for _, raw := range rawItems {
		membership, ok, mapErr := mapDirectPrincipalGroupMembership(raw, principal)
		if mapErr != nil {
			return nil, mapErr
		}
		if !ok {
			continue
		}
		out = append(out, membership)
	}
	return out, nil
}

func mapDirectPrincipalGroupMembership(raw json.RawMessage, principal facts.PrivilegedPrincipal) (facts.PrincipalGroupMembership, bool, error) {
	var payload struct {
		ID        string `json:"id"`
		ODataType string `json:"@odata.type"`
		Name      string `json:"displayName"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return facts.PrincipalGroupMembership{}, false, err
	}
	groupID := strings.TrimSpace(payload.ID)
	groupType := normalizePrincipalType(payload.ODataType)
	if groupID == "" || !strings.EqualFold(groupType, "group") {
		return facts.PrincipalGroupMembership{}, false, nil
	}
	principalID := strings.TrimSpace(principal.PrincipalID)
	return facts.PrincipalGroupMembership{
		PrincipalID:      principalID,
		PrincipalType:    strings.TrimSpace(principal.PrincipalType),
		GroupID:          groupID,
		GroupDisplayName: strings.TrimSpace(payload.Name),
		GroupType:        groupType,
		Source:           "graph:/v1.0/directoryObjects/" + principalID + "/memberOf",
	}, true, nil
}
