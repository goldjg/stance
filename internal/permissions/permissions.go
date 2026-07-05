package permissions

import (
	"fmt"
	"sort"

	"github.com/goldjg/stance-365/internal/rules"
)

var suitePermissions = map[string][]string{
	"entra": {
		"Organization.Read.All",
		"Policy.Read.All",
	},
}

func ForSuite(suite string) ([]string, error) {
	perms, ok := suitePermissions[suite]
	if !ok {
		return nil, fmt.Errorf("unknown suite: %s", suite)
	}
	return uniqueSorted(perms), nil
}

func ForChecks(checkIDs []string) ([]string, error) {
	if len(checkIDs) == 0 {
		return nil, fmt.Errorf("at least one check id is required")
	}

	ruleByID := make(map[string]rules.Rule)
	for _, r := range rules.BuiltinConditionalAccessRules() {
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
	sort.Strings(out)
	return out
}
