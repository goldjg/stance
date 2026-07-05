package rules

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Rule struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Severity            Severity `json:"severity"`
	Category            string   `json:"category"`
	Service             string   `json:"service"`
	RequiredPermissions []string `json:"required_permissions"`
	DataRequirements    []string `json:"data_requirements"`
	Remediation         string   `json:"remediation"`
	References          []string `json:"references"`
}
