package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run a script against a sample or real message",
	Long: `Execute a MailScript rule against a synthetic message built from flags,
or against a real message file, and report the actions it produced.

Examples:
  # Synthetic message from flags
  mailscript test --script=filter.star --from=spam@evil.example --subject="Buy now" -v

  # A real message, with authentication verified
  mailscript test --script=filter.star --eml=message.eml --verify --client-ip=192.0.2.1

  # Machine-readable output for CI
  mailscript test --script=filter.star --eml=message.eml --json`,
	RunE: runTest,
}

var (
	testFrom    string
	testTo      string
	testSubject string
	testBody    string
	testSpam    float64
	testEML     string
)

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().StringVar(&scriptPath, "script", "", "Path to the MailScript file (required)")
	testCmd.Flags().StringVar(&testEML, "eml", "", "Path to an RFC 5322 message to test against")
	testCmd.Flags().StringVar(&testFrom, "from", "test@example.com", "Sender address")
	testCmd.Flags().StringVar(&testTo, "to", "recipient@example.com", "Recipient address")
	testCmd.Flags().StringVar(&testSubject, "subject", "Test Message", "Subject line")
	testCmd.Flags().StringVar(&testBody, "body", "This is a test message body.", "Message body")
	testCmd.Flags().Float64Var(&testSpam, "spam-score", 0.0, "Externally supplied spam score (0-10)")
	addRuntimeFlags(testCmd)

	testCmd.MarkFlagRequired("script")
}

func runTest(cmd *cobra.Command, args []string) error {
	script, resolvedPath, err := readScript(scriptPath)
	if err != nil {
		return err
	}

	rt, err := buildRuntime()
	if err != nil {
		return err
	}

	ctx, err := buildTestContext()
	if err != nil {
		return err
	}
	ctx.SpamScore = testSpam
	rt.apply(ctx)

	if verbose && !outputJSON {
		fmt.Printf("Script:  %s\n", resolvedPath)
		fmt.Printf("From:    %s\n", ctx.Get("From"))
		fmt.Printf("To:      %s\n", ctx.Get("To"))
		fmt.Printf("Subject: %s\n", ctx.Get("Subject"))
		fmt.Println()
	}

	execErr := rules.ExecuteEngineWithOptions(script, ctx, rt.engineOptions(resolvedPath))

	if outputJSON {
		payload := map[string]interface{}{
			"status":           "success",
			"actions":          ctx.Actions,
			"logs":             ctx.LogEntries,
			"modified_headers": ctx.ModifiedHeaders,
			"score":            ctx.Score,
			"score_reasons":    ctx.ScoreReasons,
		}
		if execErr != nil {
			payload["status"] = "error"
			payload["error"] = execErr.Error()
		}
		if ctx.Verified != nil {
			payload["authentication"] = authPayload(ctx)
		}
		if len(ctx.AnalyzerResults) > 0 {
			payload["threat_analysis"] = map[string]interface{}{
				"verdict": ctx.ThreatVerdict(), "score": ctx.ThreatScore(),
				"pending": ctx.AnalysisPending(), "analyzers": ctx.AnalyzerResults,
			}
		}
		if err := printJSON(payload); err != nil {
			return err
		}
		return execErr
	}

	if execErr != nil {
		return execErr
	}

	fmt.Println("Script executed successfully.")

	fmt.Println("\nActions:")
	if len(ctx.Actions) == 0 {
		fmt.Println("(none)")
	}
	for _, action := range ctx.Actions {
		fmt.Printf("- %s\n", action)
	}

	if len(ctx.LogEntries) > 0 {
		fmt.Println("\nLog entries:")
		for _, entry := range ctx.LogEntries {
			fmt.Printf("%s\n", entry)
		}
	}

	if len(ctx.ModifiedHeaders) > 0 {
		fmt.Println("\nModified headers:")
		for k, v := range ctx.ModifiedHeaders {
			fmt.Printf("%s: %s\n", k, v)
		}
	}

	if ctx.Score != 0 {
		fmt.Printf("\nScore: %.1f\n", ctx.Score)
		for _, reason := range ctx.ScoreReasons {
			fmt.Printf("%s\n", reason)
		}
	}

	if ctx.Verified != nil {
		fmt.Printf("\nAuthentication: %s\n", ctx.Verified.Summary())
	}

	return nil
}

// buildTestContext returns the message under test, from a file when one was
// given and from the flags otherwise.
func buildTestContext() (*rules.MessageContext, error) {
	if testEML != "" {
		raw, err := os.ReadFile(testEML)
		if err != nil {
			return nil, fmt.Errorf("failed to read message: %w", err)
		}
		return rules.ParseMessage(raw)
	}

	raw := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain\r\n\r\n%s\r\n",
		testFrom, testTo, testSubject, testBody)
	return rules.ParseMessage([]byte(raw))
}

// authPayload renders verification results for JSON output.
func authPayload(ctx *rules.MessageContext) map[string]interface{} {
	result := ctx.Verified
	payload := map[string]interface{}{
		"authenticated": result.Authenticated,
		"disposition":   result.Disposition(),
		"spf":           result.SPF.Result,
		"dkim":          result.DKIM.Result,
		"dmarc":         result.DMARC.Result,
		"arc":           result.ARC.Result,
		"summary":       result.Summary(),
	}
	if warnings := result.Warnings(); len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if result.DANE != nil {
		payload["dane"] = result.DANE.Result
	}
	return payload
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func printJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}
