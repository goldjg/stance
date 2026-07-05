package version

import "fmt"

var (
	// Populated by -ldflags at build time.
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func BuildString() string {
	return fmt.Sprintf("stance version=%s commit=%s date=%s", Version, Commit, Date)
}
