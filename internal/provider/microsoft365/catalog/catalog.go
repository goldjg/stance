package catalog

import (
	"sort"
	"strings"

	corecatalog "github.com/goldjg/stance/internal/core/catalog"
	microsoft365rules "github.com/goldjg/stance/internal/provider/microsoft365/rules"
)

const ProviderName = "microsoft365"

func Provider() corecatalog.ProviderInfo {
	return corecatalog.ProviderInfo{
		Name:        ProviderName,
		DisplayName: "Microsoft 365",
		Description: "Microsoft 365 posture checks collected via direct APIs.",
		Suites:      Suites(),
	}
}

func Suites() []corecatalog.SuiteInfo {
	checks := Checks()
	checkCountBySuite := make(map[string]int)
	for _, check := range checks {
		checkCountBySuite[check.Suite]++
	}

	ids := make([]string, 0, len(checkCountBySuite))
	for id := range checkCountBySuite {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]corecatalog.SuiteInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, corecatalog.SuiteInfo{
			ID:          id,
			DisplayName: suiteDisplayName(id),
			Description: suiteDescription(id),
			Provider:    ProviderName,
			Status:      corecatalog.StatusImplemented,
			CheckCount:  checkCountBySuite[id],
		})
	}
	return out
}

func Checks() []corecatalog.CheckInfo {
	rules := microsoft365rules.BuiltinConditionalAccessRules()
	out := make([]corecatalog.CheckInfo, 0, len(rules))

	for _, rule := range rules {
		suite := strings.TrimSpace(rule.Service)
		out = append(out, corecatalog.CheckInfo{
			ID:                  rule.ID,
			Title:               rule.Title,
			Provider:            ProviderName,
			Suite:               suite,
			Category:            rule.Category,
			Service:             rule.Service,
			Severity:            string(rule.Severity),
			RequiredPermissions: append([]string(nil), rule.RequiredPermissions...),
			DataRequirements:    append([]string(nil), rule.DataRequirements...),
			Status:              corecatalog.StatusImplemented,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})

	return out
}

func suiteDisplayName(id string) string {
	switch id {
	case "entra":
		return "Entra ID"
	default:
		return strings.ToUpper(id)
	}
}

func suiteDescription(id string) string {
	switch id {
	case "entra":
		return "Microsoft Entra ID posture checks."
	default:
		return "Provider suite: " + id
	}
}
