package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	scriptPath  string
	mailboxPath string
	mailboxType string
	testMode    bool
	verbose     bool
	outputJSON  bool
	daemonURL   string
)

var rootCmd = &cobra.Command{
	Use:   "mailscript",
	Short: "MailScript: Standalone Starlark email rule processor",
	Long: `MailScript is a standalone tool for testing, debugging, and processing
email messages with Starlark-based filtering rules.

Features:
  - Offline rule testing and debugging
  - Process mbox/maildir files with custom scripts
  - Integration testing for mail filtering
  - Daemon integration for live debugging
  - JSON output for automation

Examples:
  # Test a script with sample data
  mailscript test --script=filter.star

  # Process an mbox file
  mailscript process --script=filter.star --mbox=/var/mail/ryan

  # Process a Maildir
  mailscript process --script=filter.star --maildir=~/Maildir

  # Interactive REPL for testing
  mailscript repl --script=filter.star
`,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output results as JSON")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
