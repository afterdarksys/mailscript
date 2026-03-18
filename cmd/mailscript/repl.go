package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var replCmd = &cobra.Command{
	Use:   "repl",
	Short: "Interactive MailScript REPL",
	Long: `Interactive Read-Eval-Print Loop for testing MailScript rules.

Load a script and interactively test it with different message parameters.

Examples:
  # Start REPL with a script
  mailscript repl --script=filter.star

  # Start REPL without a script (define rules interactively)
  mailscript repl
`,
	RunE: runREPL,
}

func init() {
	rootCmd.AddCommand(replCmd)
	replCmd.Flags().StringVar(&scriptPath, "script", "", "Path to initial MailScript file (optional)")
}

func runREPL(cmd *cobra.Command, args []string) error {
	fmt.Println("🚀 MailScript Interactive REPL")
	fmt.Println("Type 'help' for commands, 'exit' to quit")
	fmt.Println()

	var scriptContent string
	if scriptPath != "" {
		content, err := os.ReadFile(scriptPath)
		if err != nil {
			return fmt.Errorf("failed to read script: %w", err)
		}
		scriptContent = string(content)
		fmt.Printf("📝 Loaded script: %s\n\n", scriptPath)
	}

	// Default test message
	ctx := &rules.MessageContext{
		Headers: map[string]string{
			"From":    "test@example.com",
			"To":      "recipient@example.com",
			"Subject": "Test Message",
		},
		Body:          "This is a test message body.",
		MimeType:      "text/plain",
		SpamScore:     0.0,
		VirusStatus:   "clean",
		Actions:       []string{},
		LogEntries:    []string{},
		SenderDomain:  "example.com",
		DNSResolved:   true,
		RBLListed:     false,
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("mailscript> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		args := strings.Fields(line)
		command := args[0]

		switch command {
		case "help":
			printREPLHelp()

		case "exit", "quit":
			fmt.Println("👋 Goodbye!")
			return nil

		case "run":
			if scriptContent == "" {
				fmt.Println("❌ No script loaded. Use 'load' or 'edit' first.")
				continue
			}
			runScript(scriptContent, ctx)

		case "load":
			if len(args) < 2 {
				fmt.Println("❌ Usage: load <path>")
				continue
			}
			content, err := os.ReadFile(args[1])
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				continue
			}
			scriptContent = string(content)
			fmt.Printf("✅ Loaded script from %s\n", args[1])

		case "show":
			if scriptContent == "" {
				fmt.Println("❌ No script loaded")
				continue
			}
			fmt.Println("📜 Current script:")
			fmt.Println("---")
			fmt.Println(scriptContent)
			fmt.Println("---")

		case "set":
			if len(args) < 3 {
				fmt.Println("❌ Usage: set <header> <value>")
				continue
			}
			header := args[1]
			value := strings.Join(args[2:], " ")
			ctx.Headers[header] = value
			fmt.Printf("✅ Set %s = %s\n", header, value)

		case "get":
			if len(args) < 2 {
				fmt.Println("❌ Usage: get <header>")
				continue
			}
			header := args[1]
			if val, ok := ctx.Headers[header]; ok {
				fmt.Printf("%s: %s\n", header, val)
			} else {
				fmt.Printf("❌ Header '%s' not set\n", header)
			}

		case "headers":
			fmt.Println("📋 Current headers:")
			for k, v := range ctx.Headers {
				fmt.Printf("  %s: %s\n", k, v)
			}

		case "body":
			if len(args) < 2 {
				fmt.Printf("Current body: %s\n", ctx.Body)
				continue
			}
			ctx.Body = strings.Join(args[1:], " ")
			fmt.Printf("✅ Set body\n")

		case "spam":
			if len(args) < 2 {
				fmt.Printf("Current spam score: %.1f\n", ctx.SpamScore)
				continue
			}
			var score float64
			fmt.Sscanf(args[1], "%f", &score)
			ctx.SpamScore = score
			fmt.Printf("✅ Set spam score to %.1f\n", score)

		case "reset":
			ctx.Actions = []string{}
			ctx.LogEntries = []string{}
			ctx.ModifiedHeaders = make(map[string]string)
			fmt.Println("✅ Reset message context")

		case "edit":
			fmt.Println("📝 Enter MailScript code (end with 'END' on a line by itself):")
			var code strings.Builder
			for scanner.Scan() {
				line := scanner.Text()
				if line == "END" {
					break
				}
				code.WriteString(line)
				code.WriteString("\n")
			}
			scriptContent = code.String()
			fmt.Println("✅ Script updated")

		default:
			fmt.Printf("❌ Unknown command: %s (type 'help' for commands)\n", command)
		}
	}

	return scanner.Err()
}

func printREPLHelp() {
	fmt.Println(`
MailScript REPL Commands:

  help              Show this help message
  exit, quit        Exit the REPL

Script Management:
  load <path>       Load a MailScript from file
  show              Display the current script
  edit              Edit the script inline (end with 'END')
  run               Execute the current script

Message Context:
  set <header> <value>    Set a header value
  get <header>            Get a header value
  headers                 Show all headers
  body [text]             Get or set message body
  spam [score]            Get or set spam score (0.0-10.0)
  reset                   Reset actions and logs

Example workflow:
  mailscript> load filter.star
  mailscript> set From spam@example.com
  mailscript> set Subject "Cheap deals!!!"
  mailscript> spam 8.5
  mailscript> run
`)
}

func runScript(script string, ctx *rules.MessageContext) {
	// Reset actions and logs
	ctx.Actions = []string{}
	ctx.LogEntries = []string{}
	if ctx.ModifiedHeaders == nil {
		ctx.ModifiedHeaders = make(map[string]string)
	}

	// Execute
	if err := rules.ExecuteEngine(script, ctx); err != nil {
		fmt.Printf("❌ Script error: %v\n", err)
		return
	}

	// Display results
	fmt.Println("✅ Script executed successfully!")

	if len(ctx.Actions) > 0 {
		fmt.Println("\n📋 Actions:")
		for _, action := range ctx.Actions {
			fmt.Printf("  - %s\n", action)
		}
	} else {
		fmt.Println("\n📋 Actions: (none)")
	}

	if len(ctx.LogEntries) > 0 {
		fmt.Println("\n📜 Logs:")
		for _, entry := range ctx.LogEntries {
			fmt.Printf("  %s\n", entry)
		}
	}

	if len(ctx.ModifiedHeaders) > 0 {
		fmt.Println("\n✏️  Modified Headers:")
		for k, v := range ctx.ModifiedHeaders {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	fmt.Println()
}
