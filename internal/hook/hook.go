package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookScript = `#!/bin/sh
# cybercrit pre-commit hook — do not edit
exec cybercrit scan "$@"
`

const marker = "# cybercrit pre-commit hook"

// Write creates or overwrites .git/hooks/pre-commit with the cybercrit hook script.
// repoRoot should be the path to the repository root (containing .git/).
func Write(repoRoot string) error {
	hooksDir := filepath.Join(repoRoot, ".git", "hooks")
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git/hooks): %s", repoRoot)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	// Check for existing non-cybercrit hook
	if data, err := os.ReadFile(hookPath); err == nil {
		if len(data) > 0 && !strings.Contains(string(data), marker) {
			return fmt.Errorf("existing pre-commit hook found at %s; back it up before installing", hookPath)
		}
	}

	if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

// Remove deletes the pre-commit hook if it was installed by cybercrit.
func Remove(repoRoot string) error {
	hookPath := filepath.Join(repoRoot, ".git", "hooks", "pre-commit")

	data, err := os.ReadFile(hookPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no pre-commit hook installed")
	}
	if err != nil {
		return fmt.Errorf("read hook: %w", err)
	}

	if !strings.Contains(string(data), marker) {
		return fmt.Errorf("pre-commit hook was not installed by cybercrit, refusing to remove")
	}

	return os.Remove(hookPath)
}
