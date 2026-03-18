package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var processCmd = &cobra.Command{
	Use:   "process",
	Short: "Process mailbox files with MailScript",
	Long: `Process mbox or Maildir mailboxes and apply MailScript filtering rules.

This allows you to test your mail filtering rules on real mailbox data
before deploying them to production.

Examples:
  # Process an mbox file
  mailscript process --script=filter.star --mbox=/var/mail/ryan

  # Process a Maildir with verbose output
  mailscript process --script=filter.star --maildir=~/Maildir -v

  # Process and output JSON
  mailscript process --script=filter.star --mbox=inbox.mbox --json
`,
	RunE: runProcess,
}

var (
	mboxPath    string
	maildirPath string
	dryRun      bool
	maxMessages int
)

func init() {
	rootCmd.AddCommand(processCmd)
	processCmd.Flags().StringVar(&scriptPath, "script", "", "Path to MailScript file (required)")
	processCmd.Flags().StringVar(&mboxPath, "mbox", "", "Path to mbox file")
	processCmd.Flags().StringVar(&maildirPath, "maildir", "", "Path to Maildir directory")
	processCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Don't perform actions, just show what would happen")
	processCmd.Flags().IntVar(&maxMessages, "max", 0, "Maximum messages to process (0 = all)")
	processCmd.MarkFlagRequired("script")
}

func runProcess(cmd *cobra.Command, args []string) error {
	if mboxPath == "" && maildirPath == "" {
		return fmt.Errorf("either --mbox or --maildir must be specified")
	}

	if mboxPath != "" && maildirPath != "" {
		return fmt.Errorf("cannot specify both --mbox and --maildir")
	}

	// Read script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	if verbose {
		fmt.Printf("📝 Script: %s\n", scriptPath)
		if dryRun {
			fmt.Println("🔍 DRY RUN MODE - no actions will be performed")
		}
		fmt.Println()
	}

	var results []ProcessResult
	var err2 error

	if mboxPath != "" {
		results, err2 = processMbox(mboxPath, string(scriptContent))
	} else {
		results, err2 = processMaildir(maildirPath, string(scriptContent))
	}

	if err2 != nil {
		return err2
	}

	// Output results
	if outputJSON {
		return printJSON(map[string]interface{}{
			"total_processed": len(results),
			"messages":        results,
		})
	}

	// Print summary
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total processed: %d messages\n", len(results))

	// Count actions
	actionCounts := make(map[string]int)
	for _, result := range results {
		for _, action := range result.Actions {
			actionCounts[action]++
		}
	}

	if len(actionCounts) > 0 {
		fmt.Println("\n   Actions taken:")
		for action, count := range actionCounts {
			fmt.Printf("   - %s: %d\n", action, count)
		}
	}

	return nil
}

type ProcessResult struct {
	MessageNum int                 `json:"message_num"`
	From       string              `json:"from"`
	Subject    string              `json:"subject"`
	Actions    []string            `json:"actions"`
	Logs       []string            `json:"logs,omitempty"`
	Headers    map[string]string   `json:"modified_headers,omitempty"`
	Error      string              `json:"error,omitempty"`
}

func processMbox(path string, script string) ([]ProcessResult, error) {
	if verbose {
		fmt.Printf("📦 Processing mbox: %s\n", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open mbox: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var messageBuffer bytes.Buffer
	var results []ProcessResult
	msgNum := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		// "From " indicates a boundary
		if strings.HasPrefix(line, "From ") && messageBuffer.Len() == 0 {
			// Skip envelope line
			if err == io.EOF {
				break
			}
			continue
		}

		if strings.HasPrefix(line, "From ") && messageBuffer.Len() > 0 {
			// Process current message
			msgNum++
			if maxMessages > 0 && msgNum > maxMessages {
				break
			}
			result := processMessage(msgNum, messageBuffer.Bytes(), script)
			results = append(results, result)
			messageBuffer.Reset()
			if err == io.EOF {
				break
			}
			continue
		}

		messageBuffer.WriteString(line)

		if err == io.EOF {
			if messageBuffer.Len() > 0 {
				msgNum++
				result := processMessage(msgNum, messageBuffer.Bytes(), script)
				results = append(results, result)
			}
			break
		}
	}

	return results, nil
}

func processMaildir(path string, script string) ([]ProcessResult, error) {
	if verbose {
		fmt.Printf("📂 Processing Maildir: %s\n", path)
	}

	dirs := []string{
		filepath.Join(path, "cur"),
		filepath.Join(path, "new"),
	}

	var results []ProcessResult
	msgNum := 0

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			msgNum++
			if maxMessages > 0 && msgNum > maxMessages {
				break
			}

			filePath := filepath.Join(dir, entry.Name())
			raw, err := os.ReadFile(filePath)
			if err != nil {
				results = append(results, ProcessResult{
					MessageNum: msgNum,
					Error:      fmt.Sprintf("failed to read file: %v", err),
				})
				continue
			}

			result := processMessage(msgNum, raw, script)
			results = append(results, result)
		}

		if maxMessages > 0 && msgNum >= maxMessages {
			break
		}
	}

	return results, nil
}

func processMessage(msgNum int, raw []byte, script string) ProcessResult {
	result := ProcessResult{
		MessageNum: msgNum,
		Actions:    []string{},
		Logs:       []string{},
	}

	// Parse the message
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	from := msg.Header.Get("From")
	subject := msg.Header.Get("Subject")
	body, _ := io.ReadAll(msg.Body)

	result.From = from
	result.Subject = subject

	// Build headers map
	headers := make(map[string]string)
	for k, v := range msg.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Create message context
	ctx := &rules.MessageContext{
		Headers:         headers,
		Body:            string(body),
		MimeType:        msg.Header.Get("Content-Type"),
		SpamScore:       0.0,
		VirusStatus:     "clean",
		Actions:         []string{},
		LogEntries:      []string{},
		ModifiedHeaders: make(map[string]string),
		SenderDomain:    extractDomain(from),
		DNSResolved:     true,
		RBLListed:       false,
	}

	// Execute script
	if err := rules.ExecuteEngine(script, ctx); err != nil {
		result.Error = fmt.Sprintf("execution error: %v", err)
		return result
	}

	result.Actions = ctx.Actions
	result.Logs = ctx.LogEntries
	result.Headers = ctx.ModifiedHeaders

	if verbose {
		fmt.Printf("  [%d] From: %s | Subject: %s | Actions: %v\n",
			msgNum, truncate(from, 30), truncate(subject, 40), ctx.Actions)
	}

	return result
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
