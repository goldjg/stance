package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goldjg/stance-365/internal/auth"
	"github.com/goldjg/stance-365/internal/collect"
	"github.com/goldjg/stance-365/internal/eval"
	"github.com/goldjg/stance-365/internal/facts"
	"github.com/goldjg/stance-365/internal/graph"
	"github.com/goldjg/stance-365/internal/httpclient"
	"github.com/goldjg/stance-365/internal/permissions"
	"github.com/goldjg/stance-365/internal/report"
	"github.com/goldjg/stance-365/internal/rules"
	"github.com/goldjg/stance-365/internal/version"
)

const defaultConfigPath = "stance.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version.BuildString())
		return 0
	case "init":
		configPath := defaultConfigPath
		if len(args) > 1 {
			configPath = args[1]
		}
		if err := runInit(configPath); err != nil {
			fmt.Fprintf(stderr, "init failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "created %s\n", configPath)
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "auth":
		return runAuth(args[1:], stdout, stderr)
	case "collect":
		return runCollect(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "permissions":
		return runPermissions(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "report":
		fmt.Fprintf(stderr, "%q is planned but not implemented yet\n", strings.Join(args, " "))
		return 1
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	checkID := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--check" && i+1 < len(args) {
			checkID = args[i+1]
			i++
		}
	}
	if checkID == "" {
		fmt.Fprintln(stderr, "explain requires --check <id>")
		return 1
	}

	for _, rule := range rules.BuiltinConditionalAccessRules() {
		if rule.ID != checkID {
			continue
		}
		out, err := json.MarshalIndent(rule, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "explain failed: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(append(out, '\n'))
		return 0
	}
	fmt.Fprintf(stderr, "unknown check: %s\n", checkID)
	return 1
}

func runPermissions(args []string, stdout, stderr io.Writer) int {
	var suite string
	checks := make([]string, 0)

	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--suite":
			suite = args[i+1]
			i++
		case "--check":
			checks = append(checks, args[i+1])
			i++
		}
	}

	if suite == "" && len(checks) == 0 {
		fmt.Fprintln(stderr, "permissions requires --suite <name> or --check <id>")
		return 1
	}

	perms := make([]string, 0)
	if suite != "" {
		p, err := permissions.ForSuite(suite)
		if err != nil {
			fmt.Fprintf(stderr, "permissions failed: %v\n", err)
			return 1
		}
		perms = append(perms, p...)
	}
	if len(checks) > 0 {
		p, err := permissions.ForChecks(checks)
		if err != nil {
			fmt.Fprintf(stderr, "permissions failed: %v\n", err)
			return 1
		}
		perms = append(perms, p...)
	}

	// Deduplicate while preserving output stability.
	uniq := map[string]struct{}{}
	for _, p := range perms {
		uniq[p] = struct{}{}
	}
	sorted := make([]string, 0, len(uniq))
	for p := range uniq {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	for _, p := range sorted {
		fmt.Fprintln(stdout, p)
	}
	return 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	factsPath := ""
	format := "json"
	outPath := ""

	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--facts":
			factsPath = args[i+1]
			i++
		case "--format":
			format = args[i+1]
			i++
		case "--out":
			outPath = args[i+1]
			i++
		}
	}

	if factsPath == "" {
		fmt.Fprintln(stderr, "check requires --facts <path>")
		return 1
	}

	raw, err := os.ReadFile(factsPath)
	if err != nil {
		fmt.Fprintf(stderr, "check failed to read facts: %v\n", err)
		return 1
	}

	var bundle facts.Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(stderr, "check failed to parse facts: %v\n", err)
		return 1
	}

	result := eval.EvaluateDefault(bundle)
	var payload []byte
	switch format {
	case "json":
		payload, err = report.JSON(result)
	case "md", "markdown":
		payload = report.Markdown(result)
	case "junit":
		payload, err = report.JUnit(result)
	default:
		fmt.Fprintf(stderr, "unsupported format: %s\n", format)
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "check report generation failed: %v\n", err)
		return 1
	}

	if outPath == "" {
		_, _ = stdout.Write(payload)
		if len(payload) == 0 || payload[len(payload)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
		return 0
	}

	if err := os.WriteFile(outPath, payload, 0o600); err != nil {
		fmt.Fprintf(stderr, "check write failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s report to %s\n", format, outPath)
	return 0
}

func runCollect(args []string, stdout, stderr io.Writer) int {
	outPath := ""
	if len(args) >= 2 && args[0] == "--out" {
		outPath = args[1]
	}

	cfg, err := auth.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "collect auth configuration error: %s\n", auth.Redact(err.Error()))
		return 1
	}
	provider, err := auth.NewTokenProvider(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "collect auth provider error: %s\n", auth.Redact(err.Error()))
		return 1
	}

	hc := httpclient.New("STANCE/" + version.Version)
	gc := graph.NewClient("https://graph.microsoft.com", provider, hc)
	bundle, err := collect.RunDefault(context.Background(), gc)
	if err != nil {
		fmt.Fprintf(stderr, "collect failed: %s\n", auth.Redact(err.Error()))
		return 1
	}

	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "collect encoding failed: %v\n", err)
		return 1
	}
	payload = append(payload, '\n')

	if outPath == "" {
		_, _ = stdout.Write(payload)
		return 0
	}

	if err := os.WriteFile(outPath, payload, 0o600); err != nil {
		fmt.Fprintf(stderr, "collect write failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote facts to %s\n", outPath)
	return 0
}

func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing subcommand for auth; expected: test")
		return 1
	}
	if args[0] != "test" {
		fmt.Fprintf(stderr, "unknown auth subcommand: %s\n", args[0])
		return 1
	}

	cfg, err := auth.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "auth configuration error: %s\n", auth.Redact(err.Error()))
		return 1
	}

	provider, err := auth.NewTokenProvider(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "auth provider error: %s\n", auth.Redact(err.Error()))
		return 1
	}

	tester := auth.NewGraphTester(provider)
	result, err := tester.Test(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "auth test failed: %s\n", auth.Redact(err.Error()))
		return 1
	}

	fmt.Fprintf(stdout, "auth test ok: provider=%s tenant=%s status=%d\n", result.Provider, auth.RedactTenantID(result.TenantID), result.StatusCode)
	return 0
}

func runInit(configPath string) error {
	if configPath == "" {
		return errors.New("config path cannot be empty")
	}

	cleanPath := filepath.Clean(configPath)
	if _, err := os.Stat(cleanPath); err == nil {
		return fmt.Errorf("config already exists at %s", cleanPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(cleanPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	return os.WriteFile(cleanPath, []byte(defaultConfigFile()), 0o600)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "STANCE: Secure Tenant And Configuration Evaluator")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  stance <command> [args]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Available commands:")
	fmt.Fprintln(w, "  version      Print build and version information")
	fmt.Fprintln(w, "  init         Create a local STANCE config scaffold")
	fmt.Fprintln(w, "  auth test    Verify authentication against Graph")
	fmt.Fprintln(w, "  collect      Collect tenant facts to JSON")
	fmt.Fprintln(w, "  check        Evaluate checks from collected facts")
	fmt.Fprintln(w, "  explain      Explain implemented checks")
	fmt.Fprintln(w, "  permissions  Calculate required permissions")
	fmt.Fprintln(w, "  report       (planned) Render reports from results")
}

func defaultConfigFile() string {
	return strings.TrimSpace(`
# STANCE configuration scaffold
# v0.1 focus: Entra ID + Conditional Access (read-only).

tenant_id: ""
auth:
  mode: "oidc"
  # client credentials are fallback-only for local/dev flows.
  client_id: ""
  token_url: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
collector:
  suite: "entra"
output:
  directory: "results"
`) + "\n"
}
