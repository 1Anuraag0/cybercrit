package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

// semgrepOutput is the JSON structure returned by `semgrep --json`.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []interface{}   `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
	} `json:"extra"`
}

// SemgrepAvailable checks if semgrep is installed and reachable.
func SemgrepAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// RunSemgrep executes semgrep on only the added lines from each FileDiff.
// It writes added lines to temp files, runs semgrep, and maps findings
// back to original line numbers.
//
// If semgrep is not installed, returns nil findings and nil error (graceful skip per ANLZ-02).
func RunSemgrep(diffs []diff.FileDiff, repoRoot string) ([]Finding, error) {
	if !SemgrepAvailable() {
		return nil, nil // ANLZ-02: graceful skip
	}

	if len(diffs) == 0 {
		return nil, nil
	}

	// Create temp directory for extracted added-lines files
	tmpDir, err := os.MkdirTemp("", "cybercrit-scan-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// lineMap tracks temp-file-line -> original-file-line for remapping
	type lineMapping struct {
		OrigPath string
		OrigLine int
	}
	fileMaps := make(map[string][]lineMapping)

	// Write added lines to temp files, preserving file extensions for semgrep rule matching
	for _, fd := range diffs {
		ext := filepath.Ext(fd.Path)
		base := strings.ReplaceAll(fd.Path, string(os.PathSeparator), "_")
		base = strings.ReplaceAll(base, "/", "_")
		tmpFile := filepath.Join(tmpDir, base)
		if ext == "" {
			ext = ".txt"
		}
		if filepath.Ext(tmpFile) != ext {
			tmpFile = tmpFile + ext
		}

		var lines []string
		var mappings []lineMapping

		for _, hunk := range fd.Hunks {
			for _, line := range hunk.Lines {
				if line.Kind == diff.KindAdd {
					lines = append(lines, line.Content)
					mappings = append(mappings, lineMapping{
						OrigPath: fd.Path,
						OrigLine: line.Number,
					})
				}
			}
		}

		if len(lines) == 0 {
			continue
		}

		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
			return nil, fmt.Errorf("write temp file %s: %w", tmpFile, err)
		}
		fileMaps[tmpFile] = mappings
	}

	if len(fileMaps) == 0 {
		return nil, nil
	}

	// Run semgrep with --json output on the temp directory
	cmd := exec.Command("semgrep",
		"--config", "auto",
		"--json",
		"--quiet",
		"--no-git-ignore",
		tmpDir,
	)
	cmd.Dir = repoRoot

	out, err := cmd.CombinedOutput()
	if err != nil {
		// semgrep exits 1 when findings exist — that's expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// findings exist, output is still valid JSON
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("semgrep exited %d: %s", exitErr.ExitCode(), string(out))
		} else {
			return nil, fmt.Errorf("semgrep: %w", err)
		}
	}

	// Parse semgrep JSON output
	var result semgrepOutput
	if len(out) > 0 {
		if err := json.Unmarshal(out, &result); err != nil {
			return nil, fmt.Errorf("parse semgrep output: %w", err)
		}
	}

	// Map findings back to original file paths and line numbers
	var findings []Finding
	for _, r := range result.Results {
		mappings, ok := fileMaps[r.Path]
		if !ok {
			continue
		}

		// Remap line number (1-indexed in semgrep output)
		origPath := r.Path
		origLine := r.Start.Line
		idx := r.Start.Line - 1 // convert to 0-indexed
		if idx >= 0 && idx < len(mappings) {
			origPath = mappings[idx].OrigPath
			origLine = mappings[idx].OrigLine
		}

		findings = append(findings, Finding{
			RuleID:    r.CheckID,
			Path:      origPath,
			Line:      origLine,
			Column:    r.Start.Col,
			EndLine:   r.End.Line,
			EndColumn: r.End.Col,
			Message:   r.Extra.Message,
			Severity:  ParseSeverity(r.Extra.Severity),
			Content:   strings.TrimSpace(r.Extra.Lines),
			Source:    "semgrep",
		})
	}

	return findings, nil
}

