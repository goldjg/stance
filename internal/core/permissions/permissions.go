package permissions

import (
	"fmt"
	"sort"
)

// Provider defines provider-specific permission resolution behavior.
type Provider interface {
	Name() string
	ForSuite(suite string) ([]string, error)
	ForChecks(checkIDs []string) ([]string, error)
}

func Aggregate(provider Provider, suite string, checks []string) ([]string, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if suite == "" && len(checks) == 0 {
		return nil, fmt.Errorf("suite or checks are required")
	}

	out := make([]string, 0)
	if suite != "" {
		perms, err := provider.ForSuite(suite)
		if err != nil {
			return nil, err
		}
		out = append(out, perms...)
	}
	if len(checks) > 0 {
		perms, err := provider.ForChecks(checks)
		if err != nil {
			return nil, err
		}
		out = append(out, perms...)
	}

	uniq := map[string]struct{}{}
	for _, p := range out {
		uniq[p] = struct{}{}
	}
	sorted := make([]string, 0, len(uniq))
	for p := range uniq {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	return sorted, nil
}
