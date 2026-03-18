package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Integrate with aftermaild for live testing",
	Long: `Connect to a running aftermaild instance and apply MailScript rules
to messages in real-time. Perfect for debugging and development.

Examples:
  # Check daemon status
  mailscript daemon status

  # Test script against daemon messages
  mailscript daemon test --script=filter.star --limit=10

  # Monitor daemon and apply rules
  mailscript daemon monitor --script=filter.star
`,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check aftermaild status",
	RunE:  runDaemonStatus,
}

var daemonTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test script against daemon messages",
	RunE:  runDaemonTest,
}

var daemonMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor daemon and apply rules in real-time",
	RunE:  runDaemonMonitor,
}

var (
	limit      int
	pollInterval int
)

func init() {
	rootCmd.AddCommand(daemonCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonTestCmd)
	daemonCmd.AddCommand(daemonMonitorCmd)

	daemonCmd.PersistentFlags().StringVar(&daemonURL, "url", "http://127.0.0.1:4460", "Daemon URL")

	daemonTestCmd.Flags().StringVar(&scriptPath, "script", "", "Path to MailScript file (required)")
	daemonTestCmd.Flags().IntVar(&limit, "limit", 10, "Maximum messages to test")
	daemonTestCmd.MarkFlagRequired("script")

	daemonMonitorCmd.Flags().StringVar(&scriptPath, "script", "", "Path to MailScript file (required)")
	daemonMonitorCmd.Flags().IntVar(&pollInterval, "interval", 5, "Poll interval in seconds")
	daemonMonitorCmd.MarkFlagRequired("script")
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(daemonURL + "/api/status")
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if outputJSON {
		fmt.Println(string(body))
	} else {
		var status map[string]interface{}
		if err := json.Unmarshal(body, &status); err != nil {
			return err
		}
		fmt.Println("✅ aftermaild is online")
		for k, v := range status {
			fmt.Printf("   %s: %v\n", k, v)
		}
	}

	return nil
}

func runDaemonTest(cmd *cobra.Command, args []string) error {
	// Read script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	if verbose {
		fmt.Printf("📝 Script: %s\n", scriptPath)
		fmt.Printf("🔗 Daemon: %s\n", daemonURL)
		fmt.Printf("📊 Testing up to %d messages\n\n", limit)
	}

	// Fetch messages from daemon
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(daemonURL + "/api/v1/inbox")
	if err != nil {
		return fmt.Errorf("failed to fetch messages: %w", err)
	}
	defer resp.Body.Close()

	var messages []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return fmt.Errorf("failed to decode messages: %w", err)
	}

	if len(messages) == 0 {
		fmt.Println("ℹ️  No messages found in daemon inbox")
		return nil
	}

	processedCount := 0
	for i, msg := range messages {
		if limit > 0 && i >= limit {
			break
		}

		// Build message context from daemon message
		ctx := buildContextFromDaemonMessage(msg)

		// Execute script
		if err := rules.ExecuteEngine(string(scriptContent), ctx); err != nil {
			fmt.Printf("❌ [%d] Error: %v\n", i+1, err)
			continue
		}

		processedCount++

		if verbose {
			sender := getString(msg, "sender")
			subject := getString(msg, "subject")
			fmt.Printf("  [%d] From: %s | Subject: %s | Actions: %v\n",
				i+1, truncate(sender, 30), truncate(subject, 40), ctx.Actions)
		}
	}

	fmt.Printf("\n✅ Processed %d messages\n", processedCount)
	return nil
}

func runDaemonMonitor(cmd *cobra.Command, args []string) error {
	// Read script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	fmt.Printf("🔍 Monitoring daemon at %s\n", daemonURL)
	fmt.Printf("📝 Script: %s\n", scriptPath)
	fmt.Printf("⏱️  Poll interval: %ds\n", pollInterval)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	client := &http.Client{Timeout: 30 * time.Second}
	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	lastCount := 0

	for range ticker.C {
		resp, err := client.Get(daemonURL + "/api/v1/inbox")
		if err != nil {
			fmt.Printf("⚠️  Connection error: %v\n", err)
			continue
		}

		var messages []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
			resp.Body.Close()
			fmt.Printf("⚠️  Decode error: %v\n", err)
			continue
		}
		resp.Body.Close()

		currentCount := len(messages)
		if currentCount > lastCount {
			newMessages := currentCount - lastCount
			fmt.Printf("[%s] 📬 %d new message(s)\n", time.Now().Format("15:04:05"), newMessages)

			// Process new messages only
			for i := lastCount; i < currentCount; i++ {
				msg := messages[i]
				ctx := buildContextFromDaemonMessage(msg)

				if err := rules.ExecuteEngine(string(scriptContent), ctx); err != nil {
					fmt.Printf("  ❌ Error processing message: %v\n", err)
					continue
				}

				sender := getString(msg, "sender")
				fmt.Printf("  📧 From: %s | Actions: %v\n", truncate(sender, 40), ctx.Actions)
			}
		}

		lastCount = currentCount
	}

	return nil
}

func buildContextFromDaemonMessage(msg map[string]interface{}) *rules.MessageContext {
	headers := make(map[string]string)
	headers["From"] = getString(msg, "sender")
	headers["Subject"] = getString(msg, "subject")

	// Try to extract more headers if available
	if rawHeaders, ok := msg["raw_headers"].(string); ok {
		// Parse raw headers
		lines := strings.Split(rawHeaders, "\n")
		for _, line := range lines {
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	body := getString(msg, "body_plain")
	if body == "" {
		body = getString(msg, "body_html")
	}

	return &rules.MessageContext{
		Headers:         headers,
		Body:            body,
		MimeType:        "text/plain",
		SpamScore:       getFloat(msg, "spam_score"),
		VirusStatus:     "clean",
		Actions:         []string{},
		LogEntries:      []string{},
		ModifiedHeaders: make(map[string]string),
		SenderDomain:    extractDomain(getString(msg, "sender")),
		DNSResolved:     true,
		RBLListed:       false,
	}
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0.0
}
