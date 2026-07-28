package main

import (
	"fmt"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var lintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Check a script for errors without delivering mail",
	Long: `Parse a rule script, execute it against a synthetic message, and report
syntax errors, unknown builtins, and rules that never reach a delivery action.

Run this in CI: a script that fails to parse takes the filter offline, and a
script that reaches no action leaves delivery to the default.

Examples:
  mailscript lint --script=filter.star
  mailscript lint --script=filter.star --json`,
	RunE: runLint,
}

func init() {
	rootCmd.AddCommand(lintCmd)
	lintCmd.Flags().StringVar(&scriptPath, "script", "", "Path to the MailScript file (required)")
	addRuntimeFlags(lintCmd)
	lintCmd.MarkFlagRequired("script")
}

func runLint(cmd *cobra.Command, args []string) error {
	script, resolvedPath, err := readScript(scriptPath)
	if err != nil {
		return err
	}

	rt, err := buildRuntime()
	if err != nil {
		return err
	}

	var problems []string
	var warnings []string

	// A benign message exercises the default path through the script.
	sample := "From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@example.net>\r\n" +
		"Subject: Lint probe\r\n" +
		"Date: Mon, 27 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <lint@example.com>\r\n\r\n" +
		"Probe body.\r\n"

	ctx, err := rules.ParseMessage([]byte(sample))
	if err != nil {
		return err
	}
	rt.apply(ctx)

	if err := rules.ExecuteEngineWithOptions(script, ctx, rt.engineOptions(resolvedPath)); err != nil {
		problems = append(problems, err.Error())
	}

	if len(problems) == 0 && !reachesDeliveryAction(ctx.Actions) {
		warnings = append(warnings,
			"the script produced no delivery action for a benign message; "+
				"delivery will fall through to the default")
	}

	if strings.Contains(script, "def evaluate") == false {
		warnings = append(warnings,
			"no evaluate() function defined; the script body runs at module level")
	}

	if outputJSON {
		return printJSON(map[string]interface{}{
			"script":   resolvedPath,
			"ok":       len(problems) == 0,
			"errors":   problems,
			"warnings": warnings,
			"actions":  ctx.Actions,
		})
	}

	fmt.Printf("Script: %s\n", resolvedPath)

	if len(problems) > 0 {
		fmt.Println("\nErrors:")
		for _, p := range problems {
			fmt.Printf("%s\n", p)
		}
		return fmt.Errorf("%d error(s) found", len(problems))
	}

	fmt.Println("Parsed and executed successfully.")

	if len(ctx.Actions) > 0 {
		fmt.Printf("Actions on a benign message: %s\n", strings.Join(ctx.Actions, ", "))
	}

	if len(warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range warnings {
			fmt.Printf("%s\n", w)
		}
	}

	return nil
}

// reachesDeliveryAction reports whether the script decided the message's fate.
func reachesDeliveryAction(actions []string) bool {
	terminal := map[string]bool{
		"accept": true, "discard": true, "drop": true, "bounce": true,
		"quarantine": true, "reject": true, "defer": true,
	}

	for _, action := range actions {
		name := action
		if i := strings.Index(action, ":"); i > 0 {
			name = action[:i]
		}
		if terminal[name] || name == "fileinto" || name == "redirect" || name == "divert_to" {
			return true
		}
	}
	return false
}
