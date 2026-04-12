package patch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DryRun tests if a patch can be cleanly applied without actually applying it.
// Returns nil if the patch would apply cleanly (UI-04).
func DryRun(repoRoot, patchContent string) error {
	tmpFile, err := writeTempPatch(patchContent)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("git", "apply", "--check", "--cached", tmpFile)
	cmd.Dir = repoRoot

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("patch dry-run failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply applies a patch to the staged index using `git apply --cached --index` (UI-02).
// Only call this after DryRun returns nil.
func Apply(repoRoot, patchContent string) error {
	tmpFile, err := writeTempPatch(patchContent)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("git", "apply", "--cached", "--index", tmpFile)
	cmd.Dir = repoRoot

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("patch apply failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// writeTempPatch writes patch content to a temp file and returns the path.
func writeTempPatch(content string) (string, error) {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, "cybercrit-patch-*.diff")

	f, err := os.CreateTemp(tmpDir, "cybercrit-patch-*.diff")
	if err != nil {
		return "", fmt.Errorf("create temp patch: %w", err)
	}

	_ = tmpFile // suppress unused

	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write patch: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	return f.Name(), nil
}
