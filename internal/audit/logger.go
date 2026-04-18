package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const auditFileName = "audit.jsonl"

// Entry is a single audit log entry.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`   // "apply", "skip", "block", "bypass"
	RuleID    string `json:"rule_id"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`   // "semgrep", "llm", "fallback"
	Message   string `json:"message"`
	Reason    string `json:"reason,omitempty"`    // bypass reason
	PatchHash string `json:"patch_hash,omitempty"`
}

// Logger writes audit entries to audit.jsonl in ~/.cybercrit/<repo-hash>/.
type Logger struct {
	file *os.File
}

// Dir returns the cybercrit data directory for a given repo root.
// Creates it if it doesn't exist.
func Dir(repoRoot string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}

	// Use repo folder name as subdirectory for multi-repo support
	repoName := filepath.Base(repoRoot)
	dir := filepath.Join(home, ".cybercrit", repoName)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create audit dir: %w", err)
	}

	return dir, nil
}

// AuditFilePath returns the full path to audit.jsonl for a given repo root.
func AuditFilePath(repoRoot string) (string, error) {
	dir, err := Dir(repoRoot)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, auditFileName), nil
}

// NewLogger creates or appends to audit.jsonl in ~/.cybercrit/<repo>/.
func NewLogger(repoRoot string) (*Logger, error) {
	path, err := AuditFilePath(repoRoot)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &Logger{file: f}, nil
}

// Log writes an audit entry.
func (l *Logger) Log(entry Entry) error {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	return nil
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// ReadAll reads all audit entries from the log file for a given repo root.
func ReadAll(repoRoot string) ([]Entry, error) {
	path, err := AuditFilePath(repoRoot)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []Entry
	for _, line := range splitLines(string(data)) {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, e)
	}

	return entries, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

