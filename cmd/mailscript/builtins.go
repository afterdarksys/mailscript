package main

import (
	"fmt"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var builtinsCmd = &cobra.Command{
	Use:   "builtins",
	Short: "List every builtin available to rule scripts",
	Long: `Print the names of all functions the rule engine exposes.

The list is read from the live registration, so it always matches the binary
you are running. SPEC.md documents the signatures.

Examples:
  mailscript builtins
  mailscript builtins --filter=dkim
  mailscript builtins --json`,
	RunE: runBuiltins,
}

var builtinFilter string

func init() {
	rootCmd.AddCommand(builtinsCmd)
	builtinsCmd.Flags().StringVar(&builtinFilter, "filter", "", "Only show names containing this substring")
}

func runBuiltins(cmd *cobra.Command, args []string) error {
	all := rules.BuiltinNames()

	names := make([]string, 0, len(all))
	for _, name := range all {
		if builtinFilter == "" || strings.Contains(name, strings.ToLower(builtinFilter)) {
			names = append(names, name)
		}
	}

	if outputJSON {
		return printJSON(map[string]interface{}{
			"count":    len(names),
			"builtins": names,
		})
	}

	// Three columns keeps a 234-entry list readable in a terminal.
	const columns = 3
	width := 0
	for _, name := range names {
		if len(name) > width {
			width = len(name)
		}
	}

	for i, name := range names {
		fmt.Printf("%-*s", width+2, name)
		if (i+1)%columns == 0 {
			fmt.Println()
		}
	}
	if len(names)%columns != 0 {
		fmt.Println()
	}
	fmt.Printf("\n%d builtins\n", len(names))
	return nil
}
