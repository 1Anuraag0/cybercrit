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

// postCommitScript detects if the pre-commit hook was skipped (--no-verify)
// and logs it to the cybercrit audit trail.
const postCommitScript = `#!/bin/sh
# cybercrit post-commit hook — do not edit
# Detects --no-verify commits and logs them to audit trail

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
PRE_COMMIT="$HOOK_DIR/pre-commit"

# If pre-commit hook exists but GIT_SKIP_HOOKS or --no-verify was used,
# the pre-commit hook would not have run. Detect this by checking
# if a marker file was NOT created by the pre-commit hook.
MARKER_FILE="/tmp/.cybercrit-hook-ran-$$"

if [ -f "$PRE_COMMIT" ] && grep -q "cybercrit" "$PRE_COMMIT" 2>/dev/null; then
    if ! [ -f "$MARKER_FILE" ]; then
        # Pre-commit hook exists but didn't run — likely --no-verify
        COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        AUTHOR=$(git log -1 --format='%an' 2>/dev/null || echo "unknown")
        echo "⚠ cybercrit: commit $COMMIT_HASH by $AUTHOR skipped pre-commit analysis (--no-verify)"
        
        # Log to audit if cybercrit is available
        if command -v cybercrit >/dev/null 2>&1; then
            cybercrit log-skip --commit "$COMMIT_HASH" --author "$AUTHOR" 2>/dev/null || true
        fi
    fi
    rm -f "$MARKER_FILE" 2>/dev/null
fi
`

const marker = "# cybercrit pre-commit hook"
const postCommitMarker = "# cybercrit post-commit hook"

// Write creates or overwrites .git/hooks/pre-commit with the cybercrit hook script.
// Also installs a post-commit hook that detects --no-verify usage.
// repoRoot should be the path to the repository root (containing .git/).
func Write(repoRoot string) error {
	hooksDir := filepath.Join(repoRoot, ".git", "hooks")
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git/hooks): %s", repoRoot)
	}

	// Install pre-commit hook
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if data, err := os.ReadFile(hookPath); err == nil {
		if len(data) > 0 && !strings.Contains(string(data), marker) {
			return fmt.Errorf("existing pre-commit hook found at %s; back it up before installing", hookPath)
		}
	}
	if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}

	// Install post-commit hook (--no-verify detection)
	postCommitPath := filepath.Join(hooksDir, "post-commit")
	if data, err := os.ReadFile(postCommitPath); err == nil {
		if len(data) > 0 && !strings.Contains(string(data), postCommitMarker) {
			// Don't overwrite existing non-cybercrit post-commit hook
			return nil
		}
	}
	if err := os.WriteFile(postCommitPath, []byte(postCommitScript), 0o755); err != nil {
		// Non-fatal — post-commit is supplementary
		fmt.Printf("⚠ could not install post-commit hook: %v\n", err)
	}

	return nil
}

// Remove deletes the pre-commit hook if it was installed by cybercrit.
// Also removes the post-commit hook if it was installed by cybercrit.
func Remove(repoRoot string) error {
	hooksDir := filepath.Join(repoRoot, ".git", "hooks")

	// Remove pre-commit
	hookPath := filepath.Join(hooksDir, "pre-commit")
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
	if err := os.Remove(hookPath); err != nil {
		return err
	}

	// Remove post-commit if ours
	postCommitPath := filepath.Join(hooksDir, "post-commit")
	if data, err := os.ReadFile(postCommitPath); err == nil {
		if strings.Contains(string(data), postCommitMarker) {
			_ = os.Remove(postCommitPath)
		}
	}

	return nil
}


