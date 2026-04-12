package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const auditFile = "audit.jsonl"

// Entry is a single audit log entry.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`   // "apply", "skip", "block"
	RuleID    string `json:"rule_id"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`   // "semgrep", "llm"
	Message   string `json:"message"`
	PatchHash string `json:"patch_hash,omitempty"`
}

// Logger writes audit entries to audit.jsonl in the repo root.
type Logger struct {
	file *os.File
}

// NewLogger creates or appends to the audit.jsonl file (UI-03).
func NewLogger(repoRoot string) (*Logger, error) {
	path := filepath.Join(repoRoot, auditFile)

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
