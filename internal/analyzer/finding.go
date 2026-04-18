package analyzer

// Severity levels for findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity converts a semgrep severity string to our Severity type.
func ParseSeverity(s string) Severity {
	switch s {
	case "INFO":
		return SeverityInfo
	case "WARNING":
		return SeverityWarning
	case "ERROR":
		return SeverityError
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// Finding represents a single security finding from analysis.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	Path       string   `json:"path"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	EndLine    int      `json:"end_line"`
	EndColumn  int      `json:"end_column"`
	Message    string   `json:"message"`
	Severity   Severity `json:"severity"`
	Content    string   `json:"content"`    // the matched source line
	Source     string   `json:"source"`     // "semgrep" or "llm"
	Confidence float64  `json:"confidence"` // 0.0-1.0, used by LLM findings
	Patch      string   `json:"patch"`      // git-apply compatible patch, if available

	// LLM Metadata Extensions introduced by Multi-Agent Fallback Refactor
	LLMID       string `json:"llm_id"`
	VulnClass   string `json:"vuln_class"`
	CWE         string `json:"cwe"`
	AutoFixable bool   `json:"auto_fixable"`
	FixedLine   string `json:"fixed_line"`
	FixExplain  string `json:"fix_explain"`
	LatencyMs   int64  `json:"latency_ms"`
}

// Key returns a deduplication key for this finding.
func (f Finding) Key() string {
	return f.RuleID + ":" + f.Content
}

