package llm

import "fmt"
import "strings"

const SystemPrompt = `You are an expert security auditor specializing in code vulnerability detection.
You will be given a git diff containing only ADDED lines (+) from a developer's staged commit.

STRICT RULES:
1. Analyze ONLY the added lines. Ignore removed lines entirely.
2. Only report findings with confidence >= 0.75.
3. Every finding MUST include a ready-to-apply fixed_line.
4. NEVER hallucinate line numbers. Only reference lines present in the input.
5. If no vulnerabilities exist, return {"findings": []}.
6. description max 100 chars. explanation max 150 chars.

SEVERITY (use exactly one): CRITICAL | HIGH | MEDIUM | LOW

VULN_CLASS (use exactly one): INJECTION | SECRETS | SSRF | RCE | AUTH_BYPASS |
CRYPTO_WEAK | PATH_TRAVERSAL | INSECURE_CONFIG | IDOR | XXE | OPEN_REDIRECT

RESPOND ONLY WITH RAW JSON. NO TEXT BEFORE OR AFTER. NO MARKDOWN FENCES.
VALID RESPONSE SHAPE:
{
  "findings": [{
    "id": "<sha256(file+line+class)[:8]>",
    "severity": "CRITICAL",
    "vuln_class": "INJECTION",
    "description": "User input concatenated into SQL query string",
    "line_number": 42,
    "code_snippet": "db.Query(\"SELECT * FROM users WHERE id=\" + userId)",
    "confidence": 0.97,
    "cwe": "CWE-89",
    "fix": {
      "fixed_line": "db.Query(\"SELECT * FROM users WHERE id=?\", userId)",
      "explanation": "Replace string concat with parameterized query",
      "automated": true
    }
  }]
}`

// BuildUserMessage constructs the per-request user turn for any agent.
func BuildUserMessage(req AnalyzeRequest) string {
    return fmt.Sprintf(
        "Analyze this diff for security vulnerabilities:\nLanguage: %s\nFile: %s\n\n```diff\n%s\n```\n\nAdded lines: %d",
        req.Language, req.FilePath, req.AddedLines, req.AddedCount,
    )
}

// StripFences removes markdown code fences that Gemini/OpenRouter sometimes
// inject despite explicit instructions. Call before json.Unmarshal.
func StripFences(s string) string {
    s = strings.TrimSpace(s)
    if strings.HasPrefix(s, "```json") {
        s = strings.TrimPrefix(s, "```json")
    } else if strings.HasPrefix(s, "```") {
        s = strings.TrimPrefix(s, "```")
    }
    s = strings.TrimSuffix(s, "```")
    return strings.TrimSpace(s)
}
