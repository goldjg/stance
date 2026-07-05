package catalog

type Status string

const (
	StatusNotStarted  Status = "not-started"
	StatusPartial     Status = "partial"
	StatusImplemented Status = "implemented"
	StatusDeferred    Status = "deferred"
)

type ProviderInfo struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"display_name"`
	Description string      `json:"description"`
	Suites      []SuiteInfo `json:"suites"`
}

type SuiteInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Provider    string `json:"provider"`
	Status      Status `json:"status"`
	CheckCount  int    `json:"check_count"`
}

type CheckInfo struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Provider            string   `json:"provider"`
	Suite               string   `json:"suite"`
	Category            string   `json:"category"`
	Service             string   `json:"service"`
	Severity            string   `json:"severity"`
	RequiredPermissions []string `json:"required_permissions"`
	DataRequirements    []string `json:"data_requirements"`
	Status              Status   `json:"status"`
}
