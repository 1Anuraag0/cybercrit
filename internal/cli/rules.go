package cli

import (
	"fmt"

	"github.com/cybercrit/cybercrit/internal/analyzer"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage cybercrit detection rules",
		Long:  "List bundled rules, check version, and update to latest patterns.",
	}

	cmd.AddCommand(newRulesVersionCmd())
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesUpdateCmd())

	return cmd
}

func newRulesVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the current bundled rules version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cybercrit rules version: %s\n", analyzer.RuleVersion())
		},
	}
}

func newRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all bundled fallback rules",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Bundled Fallback Rules (v%s)\n\n", analyzer.RuleVersion())

			rules := analyzer.ListRules()
			for i, r := range rules {
				fmt.Printf("  %2d. %-30s [%s]\n", i+1, r.ID, r.Severity)
				fmt.Printf("      %s\n", r.Message)
				if len(r.FileExts) > 0 {
					fmt.Printf("      applies to: %v\n", r.FileExts)
				}
				fmt.Println()
			}

			fmt.Printf("  %d rules total\n", len(rules))
		},
	}
}

func newRulesUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Check for and apply rule updates",
		Long: `Check if a newer version of the cybercrit rule set is available.
Rule updates are bundled with new cybercrit binary releases.

To update rules, update cybercrit itself:
  go install github.com/cybercrit/cybercrit@latest

Future versions will support hot-loading rule updates from a remote registry.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Current rules version: %s\n\n", analyzer.RuleVersion())
			fmt.Println("Rules are bundled with the cybercrit binary.")
			fmt.Println("To update rules, update cybercrit:")
			fmt.Println("  go install github.com/cybercrit/cybercrit@latest")
			fmt.Println()
			fmt.Println("Rule updates include:")
			fmt.Println("  • New AWS key format patterns (ASIA*, etc.)")
			fmt.Println("  • Updated secret detection regex")
			fmt.Println("  • New vulnerability classes")
			fmt.Println()
			fmt.Printf("Pin your rule version in .cybercrit.toml:\n")
			fmt.Printf("  [rules]\n")
			fmt.Printf("  version = \"%s\"\n", analyzer.RuleVersion())
		},
	}
}
