package cli

import (
	"fmt"
	"os"

	"github.com/cybercrit/cybercrit/internal/bypass"
	"github.com/spf13/cobra"
)

func newBypassCmd() *cobra.Command {
	var reason string
	var ttlHours int

	cmd := &cobra.Command{
		Use:   "bypass",
		Short: "Create a one-time audited bypass token",
		Long: `Create a signed, one-time bypass token that allows the next commit to skip
cybercrit analysis. The bypass is audited with a mandatory reason and TTL.

Unlike git commit --no-verify, this leaves an audit trail.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			token, err := bypass.Create(wd, reason, ttlHours)
			if err != nil {
				return err
			}

			fmt.Printf("✓ bypass token created\n")
			fmt.Printf("  id:      %s\n", token.ID)
			fmt.Printf("  reason:  %s\n", token.Reason)
			fmt.Printf("  expires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("\n  next commit will skip analysis (one-time use)\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "mandatory reason for bypassing (e.g. \"hotfix for prod outage\")")
	cmd.Flags().IntVar(&ttlHours, "ttl", 1, "hours until token expires")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}
