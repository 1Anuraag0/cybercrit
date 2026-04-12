package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/cybercrit/cybercrit/internal/analyzer"
)

// llmFinding is the raw JSON shape returned by the LLM.
type llmFinding struct {
	RuleID     string  `json:"rule_id"`
	Path       string  `json:"path"`
	Line       int     `json:"line"`
	Message    string  `json:"message"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Patch      string  `json:"patch"`
}

// jsonArrayRegex extracts a JSON array from potentially wrapped LLM output.
// Handles cases where the LLM wraps the JSON in markdown code fences.
var jsonArrayRegex = regexp.MustCompile(`(?s)\[.*\]`)

// validSeverities is the set of acceptable severity values.
var validSeverities = map[string]bool{
	"INFO": true, "WARNING": true, "ERROR": true, "CRITICAL": true,
}

// validRuleIDRegex ensures rule_id is kebab-case alphanumeric.
var validRuleIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

// ParseResponse parses the LLM JSON response into typed findings (LLM-03).
// Applies strict schema validation with regex checks for patch safety.
// Filters findings below the confidence threshold (LLM-05).
func ParseResponse(raw string, confidenceThreshold float64) ([]analyzer.Finding, error) {
	// Strip markdown code fences if present
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	// Extract JSON array from response
	match := jsonArrayRegex.FindString(raw)
	if match == "" {
		// Empty array is valid — no findings
		if strings.TrimSpace(raw) == "[]" {
			return nil, nil
		}
		return nil, fmt.Errorf("LLM response does not contain a valid JSON array")
	}

	var rawFindings []llmFinding
	if err := json.Unmarshal([]byte(match), &rawFindings); err != nil {
		return nil, fmt.Errorf("parse LLM JSON: %w", err)
	}

	var findings []analyzer.Finding
	for _, rf := range rawFindings {
		// Validate required fields
		if rf.RuleID == "" || rf.Path == "" || rf.Message == "" {
			continue // skip malformed entries
		}

		// Validate rule_id format (LLM-03: regex validation)
		if !validRuleIDRegex.MatchString(rf.RuleID) {
			// Attempt to normalize: lowercase + replace spaces/underscores with hyphens
			normalized := strings.ToLower(rf.RuleID)
			normalized = strings.ReplaceAll(normalized, " ", "-")
			normalized = strings.ReplaceAll(normalized, "_", "-")
			if validRuleIDRegex.MatchString(normalized) {
				rf.RuleID = normalized
			} else {
				continue // skip if still invalid
			}
		}

		// Validate severity
		if !validSeverities[rf.Severity] {
			rf.Severity = "WARNING" // default to WARNING for unknown severities
		}

		// Validate confidence range
		if rf.Confidence < 0.0 {
			rf.Confidence = 0.0
		}
		if rf.Confidence > 1.0 {
			rf.Confidence = 1.0
		}

		// LLM-05: Filter below confidence threshold
		if rf.Confidence < confidenceThreshold {
			continue
		}

		// Validate patch safety (LLM-03: regex validation for patch)
		if rf.Patch != "" && !isValidPatch(rf.Patch) {
			rf.Patch = "" // strip unsafe patches
		}

		findings = append(findings, analyzer.Finding{
			RuleID:     rf.RuleID,
			Path:       rf.Path,
			Line:       rf.Line,
			Message:    rf.Message,
			Severity:   analyzer.ParseSeverity(rf.Severity),
			Content:    "",
			Source:     "llm",
			Confidence: rf.Confidence,
			Patch:      rf.Patch,
		})
	}

	return findings, nil
}

// isValidPatch performs basic safety validation on a patch string.
// Ensures it looks like a unified diff patch (starts with ---/+++ or @@ lines).
func isValidPatch(patch string) bool {
	lines := strings.Split(patch, "\n")
	if len(lines) < 2 {
		return false
	}

	// A valid git-apply patch should contain at least one hunk header
	hasHunk := false
	for _, line := range lines {
		if strings.HasPrefix(line, "@@") {
			hasHunk = true
			break
		}
	}

	// Also reject patches containing suspicious shell commands
	lower := strings.ToLower(patch)
	suspicious := []string{"rm -rf", "curl ", "wget ", "eval(", "exec(", "; rm ", "&&rm"}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return false
		}
	}

	return hasHunk
}
