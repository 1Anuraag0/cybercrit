package diff

import (
	"fmt"
	"os/exec"
	"strings"
)

// FileDiff represents all changes to a single file.
type FileDiff struct {
	Path  string
	Hunks []Hunk
}

// Hunk represents a contiguous block of changes.
type Hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	Lines    []Line
}

// Line represents a single diff line.
type Line struct {
	Kind    LineKind
	Content string
	Number  int // line number in the new file (0 if deleted line)
}

// LineKind identifies whether a line was added, removed, or context.
type LineKind int

const (
	KindContext LineKind = iota
	KindAdd
	KindDelete
)

// Run executes `git diff --cached --unified=3` from the given directory
// and returns the raw unified diff output.
func Run(repoRoot string) (string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--unified=3")
	cmd.Dir = repoRoot

	out, err := cmd.Output()
	if err != nil {
		// Exit code 1 means diff found changes — that's fine
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return string(out), nil
		}
		return "", fmt.Errorf("git diff: %w", err)
	}
	return string(out), nil
}

// Staged returns parsed file diffs from staged changes.
func Staged(repoRoot string) ([]FileDiff, error) {
	raw, err := Run(repoRoot)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil // empty diff — fast path
	}
	return Parse(raw)
}

