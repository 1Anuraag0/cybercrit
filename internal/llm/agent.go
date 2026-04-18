package llm

import "context"

// Agent is implemented by every backend: Gemini, OpenRouter, Ollama, Regex.
type Agent interface {
    Name()     string
    Available(ctx context.Context) bool
    Analyze(ctx context.Context, req AnalyzeRequest) (*AnalysisResult, error)
}

// AnalyzeRequest carries everything an agent needs per scan.
type AnalyzeRequest struct {
    FilePath     string
    Language     string
    AddedLines   string // only the + lines from the diff
    AddedCount   int
}

// AnalysisResult is the wire-level output from any agent.
// It is NOT the same as analyzer.Finding — do not conflate them.
type AnalysisResult struct {
    Findings  []Finding `json:"findings"`
    AgentUsed string    `json:"agent_used"`
    LatencyMs int64     `json:"latency_ms"`
}

type Finding struct {
    ID          string  `json:"id"`
    Severity    string  `json:"severity"`     // CRITICAL|HIGH|MEDIUM|LOW
    VulnClass   string  `json:"vuln_class"`   // see prompt.go enum
    Description string  `json:"description"`
    LineNumber  int     `json:"line_number"`
    CodeSnippet string  `json:"code_snippet"`
    Confidence  float64 `json:"confidence"`
    CWE         string  `json:"cwe"`
    Fix         Fix     `json:"fix"`
}

type Fix struct {
    FixedLine   string `json:"fixed_line"`
    Explanation string `json:"explanation"`
    Automated   bool   `json:"automated"`
}
