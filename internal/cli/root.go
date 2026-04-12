package cli

import (
	"github.com/spf13/cobra"
)

var version = "dev"

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cybercrit",
		Short: "Pre-commit security analysis for your code",
		Long: `Cybercrit is a hybrid-analysis CLI that runs as a git pre-commit hook,
combining local static analysis with cloud LLM review to catch
vulnerabilities before they're committed.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	cmd.AddCommand(newInstallCmd())
	cmd.AddCommand(newUninstallCmd())
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newBypassCmd())
	cmd.AddCommand(newReportCmd())

	return cmd
}

// Execute runs the root command.
func Execute() error {
	return newRootCmd().Execute()
}
