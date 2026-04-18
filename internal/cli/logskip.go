package cli

import (
	"fmt"
	"os"

	"github.com/cybercrit/cybercrit/internal/audit"
	"github.com/spf13/cobra"
)

func newLogSkipCmd() *cobra.Command {
	var commit string
	var author string

	cmd := &cobra.Command{
		Use:    "log-skip",
		Short:  "Log a --no-verify commit to the audit trail",
		Long:   "Internal command called by the post-commit hook when --no-verify is detected.",
		Hidden: true, // not for end-user use
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			logger, err := audit.NewLogger(wd)
			if err != nil {
				return err
			}
			defer logger.Close()

			return logger.Log(audit.Entry{
				Action:   "no-verify",
				RuleID:   "hook-bypass",
				Message:  fmt.Sprintf("commit %s by %s skipped pre-commit hook (--no-verify)", commit, author),
				Severity: "WARNING",
				Source:   "post-commit-hook",
			})
		},
	}

	cmd.Flags().StringVar(&commit, "commit", "unknown", "commit hash")
	cmd.Flags().StringVar(&author, "author", "unknown", "commit author")

	return cmd
}

