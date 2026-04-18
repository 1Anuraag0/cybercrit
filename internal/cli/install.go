package cli

import (
	"fmt"
	"os"

	"github.com/cybercrit/cybercrit/internal/hook"
	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install cybercrit as a git pre-commit hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if err := hook.Write(wd); err != nil {
				return err
			}

			// Add the default .cybercrit.toml template
			configPath := wd + "/.cybercrit.toml"
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				template := `# Multi-agent inference config
# inference = "hybrid"       # hybrid | local | cloud
# local_model = "gemma3:4b"  # requires: ollama pull gemma3:4b
# gemini_api_key = ""        # or: export GEMINI_API_KEY=...
# openrouter_api_key = ""    # or: export OPENROUTER_API_KEY=...
`
				_ = os.WriteFile(configPath, []byte(template), 0644)
			}

			fmt.Println("✓ cybercrit pre-commit hook installed")
			return nil
		},
	}
}

