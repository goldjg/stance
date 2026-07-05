package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

type PrivilegedPrincipalGroupMembershipCollector struct{}

func (PrivilegedPrincipalGroupMembershipCollector) Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error {
	seen := make(map[string]struct{})
	collected := make([]facts.PrincipalGroupMembership, 0)
	resolutions := make([]facts.PrincipalGroupResolution, 0, len(bundle.PrivilegedPrincipals))

	for _, principal := range bundle.PrivilegedPrincipals {
		principalID := strings.TrimSpace(principal.PrincipalID)
		if principalID == "" {
			continue
		}
		items, err := collectDirectGroupMembershipsForPrincipal(ctx, client, principal)
		if err != nil {
			errorKind, errorMessage := classifyGroupResolutionError(err)
			resolutions = append(resolutions, facts.PrincipalGroupResolution{
				PrincipalID:      principalID,
				PrincipalType:    strings.TrimSpace(principal.PrincipalType),
				Resolved:         false,
				DirectGroupCount: 0,
				ErrorKind:        errorKind,
				ErrorMessage:     errorMessage,
				Source:           "graph:/v1.0/directoryObjects/" + principalID + "/memberOf",
			})
			continue
		}
		retainedCount := 0
		for _, item := range items {
			key := principalID + "|" + strings.TrimSpace(item.GroupID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			collected = append(collected, item)
			retainedCount++
		}
		resolutions = append(resolutions, facts.PrincipalGroupResolution{
			PrincipalID:      principalID,
			PrincipalType:    strings.TrimSpace(principal.PrincipalType),
			Resolved:         true,
			DirectGroupCount: retainedCount,
			Source:           "graph:/v1.0/directoryObjects/" + principalID + "/memberOf",
		})
	}

	sort.Slice(collected, func(i, j int) bool {
		if collected[i].PrincipalID != collected[j].PrincipalID {
			return collected[i].PrincipalID < collected[j].PrincipalID
		}
		return collected[i].GroupID < collected[j].GroupID
	})
	sort.Slice(resolutions, func(i, j int) bool {
		if resolutions[i].PrincipalID != resolutions[j].PrincipalID {
			return resolutions[i].PrincipalID < resolutions[j].PrincipalID
		}
		return resolutions[i].Source < resolutions[j].Source
	})
	bundle.PrincipalGroupMemberships = append(bundle.PrincipalGroupMemberships, collected...)
	bundle.PrincipalGroupResolutions = append(bundle.PrincipalGroupResolutions, resolutions...)
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
		return facts.PrincipalGroupMembership{}, false, fmt.Errorf("decode direct group membership object: %w", err)
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

var graphStatusCodePattern = regexp.MustCompile(`graph returned status\s+(\d+)`)

func classifyGroupResolutionError(err error) (string, string) {
	if err == nil {
		return "", ""
	}

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return "decode_error", "failed to decode direct group membership response"
	}

	if strings.Contains(strings.ToLower(err.Error()), "decode direct group membership object") {
		return "decode_error", "failed to decode direct group membership response"
	}

	matches := graphStatusCodePattern.FindStringSubmatch(err.Error())
	if len(matches) == 2 {
		return "graph_error", "graph returned status " + matches[1]
	}

	if strings.Contains(strings.ToLower(err.Error()), "graph returned status") {
		return "graph_error", "graph returned an error"
	}

	return "unknown", "direct group membership lookup failed"
}
