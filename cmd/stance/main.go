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

	corecatalog "github.com/goldjg/stance/internal/core/catalog"
	corepermissions "github.com/goldjg/stance/internal/core/permissions"
	"github.com/goldjg/stance/internal/core/report"
	"github.com/goldjg/stance/internal/httpclient"
	microsoft365auth "github.com/goldjg/stance/internal/provider/microsoft365/auth"
	microsoft365catalog "github.com/goldjg/stance/internal/provider/microsoft365/catalog"
	microsoft365collect "github.com/goldjg/stance/internal/provider/microsoft365/collect"
	microsoft365eval "github.com/goldjg/stance/internal/provider/microsoft365/eval"
	microsoft365facts "github.com/goldjg/stance/internal/provider/microsoft365/facts"
	microsoft365graph "github.com/goldjg/stance/internal/provider/microsoft365/graph"
	microsoft365permissions "github.com/goldjg/stance/internal/provider/microsoft365/permissions"
	microsoft365rules "github.com/goldjg/stance/internal/provider/microsoft365/rules"
	"github.com/goldjg/stance/internal/version"
)

const defaultConfigPath = "stance.yaml"
const defaultProvider = "microsoft365"

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
	case "providers":
		return runProviders(args[1:], stdout, stderr)
	case "suites":
		return runSuites(args[1:], stdout, stderr)
	case "checks":
		return runChecks(args[1:], stdout, stderr)
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
	providerName, filtered, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	checkID := ""
	for i := 0; i < len(filtered); i++ {
		if filtered[i] == "--check" && i+1 < len(filtered) {
			checkID = filtered[i+1]
			i++
		}
	}
	if checkID == "" {
		fmt.Fprintln(stderr, "explain requires --check <id>")
		return 1
	}

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	for _, rule := range microsoft365rules.BuiltinConditionalAccessRules() {
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
	providerName, filtered, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var suite string
	checks := make([]string, 0)

	for i := 0; i < len(filtered); i++ {
		if i+1 >= len(filtered) {
			break
		}
		switch filtered[i] {
		case "--suite":
			suite = filtered[i+1]
			i++
		case "--check":
			checks = append(checks, filtered[i+1])
			i++
		}
	}

	if suite == "" && len(checks) == 0 {
		fmt.Fprintln(stderr, "permissions requires --suite <name> or --check <id>")
		return 1
	}

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	sorted, err := corepermissions.Aggregate(microsoft365permissions.Resolver{}, suite, checks)
	if err != nil {
		fmt.Fprintf(stderr, "permissions failed: %v\n", err)
		return 1
	}
	for _, p := range sorted {
		fmt.Fprintln(stdout, p)
	}
	return 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	providerName, filtered, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	factsPath := ""
	format := "json"
	outPath := ""

	for i := 0; i < len(filtered); i++ {
		if i+1 >= len(filtered) {
			break
		}
		switch filtered[i] {
		case "--facts":
			factsPath = filtered[i+1]
			i++
		case "--format":
			format = filtered[i+1]
			i++
		case "--out":
			outPath = filtered[i+1]
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

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	var bundle microsoft365facts.Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(stderr, "check failed to parse facts: %v\n", err)
		return 1
	}

	result := microsoft365eval.EvaluateDefault(bundle)
	var payload []byte
	switch format {
	case "json":
		payload, err = report.JSON(result)
	case "md", "markdown":
		payload = report.Markdown(result)
	case "junit":
		payload, err = report.JUnit(result)
	case "html":
		payload, err = report.HTML(result)
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

func runProviders(_ []string, stdout, _ io.Writer) int {
	providers := []corecatalog.ProviderInfo{
		microsoft365catalog.Provider(),
	}
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Name < providers[j].Name
	})
	for _, provider := range providers {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%d suites\n", provider.Name, provider.DisplayName, provider.Description, len(provider.Suites))
	}
	return 0
}

func runSuites(args []string, stdout, stderr io.Writer) int {
	providerName, _, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	for _, suite := range microsoft365catalog.Suites() {
		fmt.Fprintf(stdout, "%s\t%s\t%s\tchecks=%d\n", suite.ID, suite.DisplayName, suite.Status, suite.CheckCount)
	}
	return 0
}

func runChecks(args []string, stdout, stderr io.Writer) int {
	providerName, filtered, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	suite := ""
	format := "text"
	for i := 0; i < len(filtered); i++ {
		if i+1 >= len(filtered) {
			break
		}
		switch filtered[i] {
		case "--suite":
			suite = filtered[i+1]
			i++
		case "--format":
			format = filtered[i+1]
			i++
		}
	}

	checks := microsoft365catalog.Checks()
	if suite != "" {
		out := make([]corecatalog.CheckInfo, 0, len(checks))
		for _, check := range checks {
			if check.Suite == suite {
				out = append(out, check)
			}
		}
		checks = out
	}

	switch format {
	case "text":
		for _, check := range checks {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", check.ID, check.Severity, check.Suite, check.Title)
		}
	case "json":
		payload, marshalErr := json.MarshalIndent(checks, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(stderr, "checks failed: %v\n", marshalErr)
			return 1
		}
		_, _ = stdout.Write(append(payload, '\n'))
	default:
		fmt.Fprintf(stderr, "unsupported format: %s\n", format)
		return 1
	}

	return 0
}

func runCollect(args []string, stdout, stderr io.Writer) int {
	providerName, filtered, err := parseProviderFlag(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	outPath := ""
	for i := 0; i < len(filtered); i++ {
		if filtered[i] == "--out" && i+1 < len(filtered) {
			outPath = filtered[i+1]
			i++
		}
	}

	if providerName != defaultProvider {
		fmt.Fprintf(stderr, "unsupported provider: %s\n", providerName)
		return 1
	}

	cfg, err := microsoft365auth.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "collect auth configuration error: %s\n", microsoft365auth.Redact(err.Error()))
		return 1
	}
	provider, err := microsoft365auth.NewTokenProvider(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "collect auth provider error: %s\n", microsoft365auth.Redact(err.Error()))
		return 1
	}

	hc := httpclient.New("STANCE/" + version.Version)
	gc := microsoft365graph.NewClient("https://graph.microsoft.com", provider, hc)
	bundle, err := microsoft365collect.RunDefault(context.Background(), gc)
	if err != nil {
		fmt.Fprintf(stderr, "collect failed: %s\n", microsoft365auth.Redact(err.Error()))
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

	cfg, err := microsoft365auth.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "auth configuration error: %s\n", microsoft365auth.Redact(err.Error()))
		return 1
	}

	provider, err := microsoft365auth.NewTokenProvider(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "auth provider error: %s\n", microsoft365auth.Redact(err.Error()))
		return 1
	}

	tester := microsoft365auth.NewGraphTester(provider)
	result, err := tester.Test(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "auth test failed: %s\n", microsoft365auth.Redact(err.Error()))
		return 1
	}

	fmt.Fprintf(stdout, "auth test ok: provider=%s tenant=%s status=%d\n", result.Provider, microsoft365auth.RedactTenantID(result.TenantID), result.StatusCode)
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
	fmt.Fprintln(w, "  provider-aware commands default to --provider microsoft365")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Available commands:")
	fmt.Fprintln(w, "  version      Print build and version information")
	fmt.Fprintln(w, "  init         Create a local STANCE config scaffold")
	fmt.Fprintln(w, "  auth test    Verify authentication against Graph")
	fmt.Fprintln(w, "  collect      Collect tenant facts to JSON (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  check        Evaluate checks from collected facts (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  explain      Explain implemented checks (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  permissions  Calculate required permissions (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  providers    List implemented providers")
	fmt.Fprintln(w, "  suites       List suites for a provider (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  checks       List checks for a provider (--provider defaults to microsoft365)")
	fmt.Fprintln(w, "  report       (planned) Render reports from results")
}

func defaultConfigFile() string {
	return strings.TrimSpace(`
# STANCE configuration scaffold
# v0.1 focus: Entra ID + Conditional Access (read-only).

tenant_id: ""
provider: "microsoft365"
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

func parseProviderFlag(args []string) (string, []string, error) {
	provider := defaultProvider
	filtered := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		if args[i] == "--provider" {
			if i+1 >= len(args) {
				return "", nil, errors.New("missing value for --provider")
			}
			provider = args[i+1]
			i++
			continue
		}
		filtered = append(filtered, args[i])
	}

	if provider == "" {
		return "", nil, errors.New("provider cannot be empty")
	}
	return provider, filtered, nil
}
