package version

import (
	"strings"
	"testing"
)

func TestBuildString(t *testing.T) {
	out := BuildString()
	wantParts := []string{"stance version=", "commit=", "date="}
	for _, part := range wantParts {
		if !strings.Contains(out, part) {
			t.Fatalf("build string %q missing %q", out, part)
		}
	}
}
