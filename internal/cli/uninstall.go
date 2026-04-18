package cli

import (
	"fmt"
	"os"

	"github.com/cybercrit/cybercrit/internal/hook"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove cybercrit pre-commit hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if err := hook.Remove(wd); err != nil {
				return err
			}
			fmt.Println("✓ cybercrit pre-commit hook removed")
			return nil
		},
	}
}

