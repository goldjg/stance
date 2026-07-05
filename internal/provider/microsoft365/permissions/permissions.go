package permissions

import (
	"fmt"

	corerules "github.com/goldjg/stance/internal/core/rules"
	microsoft365catalog "github.com/goldjg/stance/internal/provider/microsoft365/catalog"
	providerrules "github.com/goldjg/stance/internal/provider/microsoft365/rules"
)

var suitePermissions = map[string][]string{
	"entra": {
		"Organization.Read.All",
		"Policy.Read.All",
		"RoleManagement.Read.Directory",
		"Directory.Read.All",
	},
}

type Resolver struct{}

func (Resolver) Name() string {
	return microsoft365catalog.ProviderName
}

func (Resolver) ForSuite(suite string) ([]string, error) {
	perms, ok := suitePermissions[suite]
	if !ok {
		return nil, fmt.Errorf("unknown suite: %s", suite)
	}
	return uniqueSorted(perms), nil
}

func (Resolver) ForChecks(checkIDs []string) ([]string, error) {
	if len(checkIDs) == 0 {
		return nil, fmt.Errorf("at least one check id is required")
	}

	ruleByID := make(map[string]corerules.Rule)
	for _, r := range providerrules.BuiltinRules() {
		ruleByID[r.ID] = r
	}

	agg := make([]string, 0)
	for _, id := range checkIDs {
		r, ok := ruleByID[id]
		if !ok {
			return nil, fmt.Errorf("unknown check: %s", id)
		}
		agg = append(agg, r.RequiredPermissions...)
	}
	return uniqueSorted(agg), nil
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
