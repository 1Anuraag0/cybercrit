package llm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

const systemPrompt = `You are a security-focused code reviewer. Analyze the following code diff for security vulnerabilities.

You will receive:
1. The code diff (added/removed lines)
2. Related files for cross-file context (if available) — use these to detect auth bypasses, missing middleware, etc.

RULES:
1. Only report REAL, EXPLOITABLE vulnerabilities — not style issues.
2. Focus on: injection, auth bypass, hardcoded secrets, path traversal, XSS, SSRF, insecure crypto, race conditions.
3. Do NOT report: missing comments, formatting, naming conventions, or theoretical issues.
4. Each finding MUST include a confidence score (0.0 to 1.0).
5. If you can suggest a fix, provide a git-apply compatible patch.
6. Use related files to detect CROSS-FILE vulnerabilities (e.g., route without auth middleware).

You MUST respond with ONLY a JSON array. No markdown, no explanation, no wrapping.
Each element must match this exact schema:

[
  {
    "rule_id": "string — a short kebab-case identifier like 'sql-injection' or 'hardcoded-secret'",
    "path": "string — the file path from the diff",
    "line": "number — the line number in the new file",
    "message": "string — a clear, actionable description of the vulnerability",
    "severity": "string — one of: INFO, WARNING, ERROR, CRITICAL",
    "confidence": "number — 0.0 to 1.0",
    "patch": "string — a git-apply compatible patch, or empty string if no fix"
  }
]

If no vulnerabilities are found, respond with: []`

// BuildUserPrompt constructs the user prompt from filtered diffs,
// applying token budget truncation (LLM-02).
//
// maxTokens is the approximate token budget. We estimate ~4 chars per token.
// If the diff exceeds the budget, we drop the lowest-complexity hunks first.
func BuildUserPrompt(diffs []diff.FileDiff, maxTokens int) string {
	return BuildUserPromptWithContext(diffs, nil, maxTokens)
}

// BuildUserPromptWithContext constructs the prompt with optional cross-file context.
func BuildUserPromptWithContext(diffs []diff.FileDiff, relatedFiles []RelatedFile, maxTokens int) string {
	if len(diffs) == 0 {
		return "No code changes to review."
	}

	// Build per-file diff strings with complexity scores
	type filePart struct {
		path       string
		content    string
		complexity int // number of added lines (proxy for complexity)
		charCount  int
	}

	var parts []filePart
	for _, fd := range diffs {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n", fd.Path, fd.Path))

		addedLines := 0
		for _, hunk := range fd.Hunks {
			sb.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n",
				hunk.OldStart, hunk.OldCount, hunk.NewStart, hunk.NewCount))
			for _, line := range hunk.Lines {
				switch line.Kind {
				case diff.KindAdd:
					sb.WriteString("+" + line.Content + "\n")
					addedLines++
				case diff.KindDelete:
					sb.WriteString("-" + line.Content + "\n")
				case diff.KindContext:
					sb.WriteString(" " + line.Content + "\n")
				}
			}
		}

		content := sb.String()
		parts = append(parts, filePart{
			path:       fd.Path,
			content:    content,
			complexity: addedLines,
			charCount:  len(content),
		})
	}

	// Sort by complexity descending (keep most complex files first)
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].complexity > parts[j].complexity
	})

	// Apply token budget (LLM-02): ~4 chars per token
	// Reserve 20% of budget for related files context
	contextBudget := 0
	if len(relatedFiles) > 0 {
		contextBudget = (maxTokens * 4) / 5 // 20% for context
	}
	diffBudget := (maxTokens * 4) - contextBudget

	var selected []string
	totalChars := 0

	for _, p := range parts {
		if totalChars+p.charCount > diffBudget && len(selected) > 0 {
			break
		}
		selected = append(selected, p.content)
		totalChars += p.charCount
	}

	var sb strings.Builder
	sb.WriteString("Review the following code diff for security vulnerabilities:\n\n")
	sb.WriteString(strings.Join(selected, "\n"))

	// Append cross-file context if available
	if len(relatedFiles) > 0 {
		sb.WriteString("\n\n--- RELATED FILES (for cross-file context) ---\n\n")
		contextChars := 0
		for _, rf := range relatedFiles {
			entry := fmt.Sprintf("// File: %s (reason: %s)\n%s\n\n", rf.Path, rf.Reason, rf.Content)
			if contextChars+len(entry) > contextBudget && contextChars > 0 {
				break
			}
			sb.WriteString(entry)
			contextChars += len(entry)
		}
	}

	return sb.String()
}

// SystemPrompt returns the system prompt for the LLM.
func SystemPrompt() string {
	return systemPrompt
}


