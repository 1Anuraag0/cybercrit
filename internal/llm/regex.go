package llm

import (
    "context"
    "crypto/sha256"
    "fmt"
    "regexp"
    "strings"
)

// All patterns compiled at init time — never in the hot path.
var regexRules []regexRule

type regexRule struct {
    pattern   *regexp.Regexp
    vulnClass string
    severity  string
    cwe       string
    desc      string
    confidence float64
}

func init() {
    regexRules = []regexRule{
        {regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
            "SECRETS", "CRITICAL", "CWE-798", "Hardcoded AWS access key", 0.80},
        {regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`),
            "SECRETS", "CRITICAL", "CWE-321", "Private key embedded in source", 0.80},
        {regexp.MustCompile(`(?i)(query|sql)\s*:?=\s*"[^"]*"\s*\+`),
            "INJECTION", "HIGH", "CWE-89", "SQL string concatenation detected", 0.75},
        {regexp.MustCompile(`\beval\s*\(`),
            "RCE", "HIGH", "CWE-95", "eval() call with possible user input", 0.75},
        {regexp.MustCompile(`(?i)sslmode\s*=\s*["']?disable`),
            "INSECURE_CONFIG", "HIGH", "CWE-311", "TLS disabled on DB connection", 0.78},
        {regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`),
            "SECRETS", "HIGH", "CWE-259", "Hardcoded password in source", 0.72},
        {regexp.MustCompile(`(?i)(md5|sha1)\s*\.new|hashlib\.(md5|sha1)`),
            "CRYPTO_WEAK", "MEDIUM", "CWE-327", "Weak hashing algorithm used", 0.70},
        {regexp.MustCompile(`Access-Control-Allow-Origin[^\n]*\*`),
            "AUTH_BYPASS", "MEDIUM", "CWE-942", "CORS wildcard allows any origin", 0.70},
        {regexp.MustCompile(`(?i)(DEBUG|debug)\s*[:=]\s*(true|True|1)\b`),
            "INSECURE_CONFIG", "LOW", "CWE-489", "Debug mode enabled in code", 0.65},
        {regexp.MustCompile(`(?i)(secret|api_key|apikey|token)\s*[:=]\s*["'][a-zA-Z0-9+/]{16,}["']`),
            "SECRETS", "HIGH", "CWE-798", "Hardcoded secret or token detected", 0.72},
    }
}

type RegexAgent struct{}

func NewRegexAgent() *RegexAgent { return &RegexAgent{} }

func (a *RegexAgent) Name() string { return "regex-builtin" }

// Available always returns true — regex has zero dependencies.
func (a *RegexAgent) Available(_ context.Context) bool { return true }

func (a *RegexAgent) Analyze(_ context.Context, req AnalyzeRequest) (*AnalysisResult, error) {
    var findings []Finding

    lines := strings.Split(req.AddedLines, "\n")
    for i, line := range lines {
        for _, rule := range regexRules {
            if !rule.pattern.MatchString(line) {
                continue
            }
            snippet := strings.TrimSpace(line)
            if len(snippet) > 120 {
                snippet = snippet[:120]
            }
            id := sha256ID(req.FilePath, i+1, rule.vulnClass)
            findings = append(findings, Finding{
                ID:          id,
                Severity:    rule.severity,
                VulnClass:   rule.vulnClass,
                Description: rule.desc,
                LineNumber:  i + 1,
                CodeSnippet: snippet,
                Confidence:  rule.confidence,
                CWE:         rule.cwe,
                Fix: Fix{
                    // regex can detect but cannot generate a fix
                    Automated:   false,
                    Explanation: rule.desc + " — manual remediation required",
                },
            })
            break // one rule per line is enough
        }
    }

    return &AnalysisResult{Findings: findings}, nil
}

// sha256ID returns the first 8 hex chars of sha256(file+line+class).
func sha256ID(file string, line int, class string) string {
    h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", file, line, class)))
    return fmt.Sprintf("%x", h)[:8]
}
