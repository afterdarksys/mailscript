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
	Short: "Test a MailScript with sample data",
	Long: `Test a MailScript rule with sample email data to verify it works correctly.

This is perfect for offline development and debugging of mail filtering rules.

Examples:
  # Test with default sample message
  mailscript test --script=filter.star

  # Test with custom headers
  mailscript test --script=filter.star --from=alice@example.com --subject="Test"
`,
	RunE: runTest,
}

var (
	testFrom    string
	testTo      string
	testSubject string
	testBody    string
)

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.Flags().StringVar(&scriptPath, "script", "", "Path to MailScript file (required)")
	testCmd.Flags().StringVar(&testFrom, "from", "test@example.com", "Test sender email")
	testCmd.Flags().StringVar(&testTo, "to", "recipient@example.com", "Test recipient email")
	testCmd.Flags().StringVar(&testSubject, "subject", "Test Message", "Test subject line")
	testCmd.Flags().StringVar(&testBody, "body", "This is a test message body.", "Test message body")
	testCmd.MarkFlagRequired("script")
}

func runTest(cmd *cobra.Command, args []string) error {
	// Read the script file
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	// Create test message context
	ctx := &rules.MessageContext{
		Headers: map[string]string{
			"From":    testFrom,
			"To":      testTo,
			"Subject": testSubject,
		},
		Body:          testBody,
		MimeType:      "text/plain",
		SpamScore:     0.0,
		VirusStatus:   "clean",
		Actions:       []string{},
		LogEntries:    []string{},
		SenderDomain:  extractDomain(testFrom),
		DNSResolved:   true,
		RBLListed:     false,
	}

	if verbose {
		fmt.Printf("📝 Testing script: %s\n", scriptPath)
		fmt.Printf("📧 Test Message:\n")
		fmt.Printf("   From: %s\n", testFrom)
		fmt.Printf("   To: %s\n", testTo)
		fmt.Printf("   Subject: %s\n", testSubject)
		fmt.Printf("   Body: %s\n\n", testBody)
	}

	// Execute the script
	if err := rules.ExecuteEngine(string(scriptContent), ctx); err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}

	// Display results
	if outputJSON {
		return printJSON(map[string]interface{}{
			"status":          "success",
			"actions":         ctx.Actions,
			"logs":            ctx.LogEntries,
			"modified_headers": ctx.ModifiedHeaders,
		})
	}

	fmt.Println("✅ Script executed successfully!")
	fmt.Println("\n📋 Actions taken:")
	if len(ctx.Actions) == 0 {
		fmt.Println("   (none)")
	}
	for _, action := range ctx.Actions {
		fmt.Printf("   - %s\n", action)
	}

	if len(ctx.LogEntries) > 0 {
		fmt.Println("\n📜 Log entries:")
		for _, entry := range ctx.LogEntries {
			fmt.Printf("   %s\n", entry)
		}
	}

	if len(ctx.ModifiedHeaders) > 0 {
		fmt.Println("\n✏️  Modified headers:")
		for k, v := range ctx.ModifiedHeaders {
			fmt.Printf("   %s: %s\n", k, v)
		}
	}

	return nil
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
