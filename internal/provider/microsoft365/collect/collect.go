package collect

import (
	"context"
	"encoding/json"

	"github.com/goldjg/stance/internal/provider/microsoft365/facts"
	"github.com/goldjg/stance/internal/provider/microsoft365/graph"
)

type Collector interface {
	Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error
}

func RunDefault(ctx context.Context, client *graph.Client) (facts.Bundle, error) {
	bundle := facts.NewBundle()
	collectors := []Collector{
		OrganizationCollector{},
		ConditionalAccessCollector{},
	}

	for _, collector := range collectors {
		if err := collector.Collect(ctx, client, &bundle); err != nil {
			return facts.Bundle{}, err
		}
	}

	return bundle, nil
}

type OrganizationCollector struct{}

func (OrganizationCollector) Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error {
	var payload struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			TenantType  string `json:"tenantType"`
		} `json:"value"`
	}
	if err := client.GetJSON(ctx, "/v1.0/organization?$top=1", &payload); err != nil {
		return err
	}
	for _, org := range payload.Value {
		bundle.Organization = append(bundle.Organization, facts.OrganizationFact{
			ID:          org.ID,
			DisplayName: org.DisplayName,
			TenantType:  org.TenantType,
		})
	}
	return nil
}

type ConditionalAccessCollector struct{}

func (ConditionalAccessCollector) Collect(ctx context.Context, client *graph.Client, bundle *facts.Bundle) error {
	rawPolicies, err := client.CollectPaginated(ctx, "/v1.0/identity/conditionalAccess/policies?$top=50")
	if err != nil {
		return err
	}

	for _, raw := range rawPolicies {
		policy, err := mapCAPolicy(raw)
		if err != nil {
			return err
		}
		bundle.CAPolicies = append(bundle.CAPolicies, policy)
	}
	return nil
}

func mapCAPolicy(raw json.RawMessage) (facts.CAPolicyFact, error) {
	var payload struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		State       string `json:"state"`
		Conditions  struct {
			Users struct {
				IncludeUsers  []string `json:"includeUsers"`
				ExcludeUsers  []string `json:"excludeUsers"`
				IncludeGroups []string `json:"includeGroups"`
				ExcludeGroups []string `json:"excludeGroups"`
				IncludeRoles  []string `json:"includeRoles"`
				ExcludeRoles  []string `json:"excludeRoles"`
			} `json:"users"`
		} `json:"conditions"`
		GrantControls struct {
			BuiltInControls        []string `json:"builtInControls"`
			AuthenticationStrength struct {
				DisplayName string `json:"displayName"`
			} `json:"authenticationStrength"`
		} `json:"grantControls"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return facts.CAPolicyFact{}, err
	}

	return facts.CAPolicyFact{
		ID:                     payload.ID,
		DisplayName:            payload.DisplayName,
		State:                  payload.State,
		IncludedUsers:          payload.Conditions.Users.IncludeUsers,
		ExcludedUsers:          payload.Conditions.Users.ExcludeUsers,
		IncludedGroups:         payload.Conditions.Users.IncludeGroups,
		ExcludedGroups:         payload.Conditions.Users.ExcludeGroups,
		IncludedRoles:          payload.Conditions.Users.IncludeRoles,
		ExcludedRoles:          payload.Conditions.Users.ExcludeRoles,
		BuiltInControls:        payload.GrantControls.BuiltInControls,
		AuthenticationStrength: payload.GrantControls.AuthenticationStrength.DisplayName,
	}, nil
}
