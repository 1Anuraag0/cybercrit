package analyzer

import (
	"regexp"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

// RulesVersion is the semantic version of the bundled fallback rule set.
// Bump this when rules are added, modified, or patterns updated.
const RulesVersion = "1.0.0"

// RuleVersion returns the current bundled rules version.
func RuleVersion() string {
	return RulesVersion
}

// fallbackRule is a hardcoded regex-based detection pattern.
// These run when semgrep is unavailable, providing a zero-dependency backstop.
type fallbackRule struct {
	ID       string
	Pattern  *regexp.Regexp
	Message  string
	Severity Severity
	// FileExts limits the rule to certain file extensions (nil = all files)
	FileExts []string
}

var fallbackRules = []fallbackRule{
	// ─── Hardcoded secrets ──────────────────────────────────────
	{
		ID:       "fallback-hardcoded-aws-key",
		Pattern:  regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		Message:  "Possible hardcoded AWS access key detected",
		Severity: SeverityCritical,
	},
	{
		ID:       "fallback-hardcoded-secret",
		Pattern:  regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|password|token|auth[_-]?token)\s*[:=]\s*["'][\w/+=-]{8,}["']`),
		Message:  "Possible hardcoded secret or credential",
		Severity: SeverityError,
	},
	{
		ID:       "fallback-private-key",
		Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----`),
		Message:  "Private key embedded in source code",
		Severity: SeverityCritical,
	},

	// ─── Injection ──────────────────────────────────────────────
	{
		ID:       "fallback-sql-concat",
		Pattern:  regexp.MustCompile(`(?i)(query|exec|execute|raw)\s*\(\s*["']?\s*SELECT|INSERT|UPDATE|DELETE.*\+`),
		Message:  "Possible SQL injection via string concatenation",
		Severity: SeverityError,
		FileExts: []string{".go", ".py", ".js", ".ts", ".java", ".rb", ".php"},
	},
	{
		ID:       "fallback-eval-usage",
		Pattern:  regexp.MustCompile(`\beval\s*\(`),
		Message:  "Use of eval() — potential code injection vector",
		Severity: SeverityError,
		FileExts: []string{".js", ".ts", ".py", ".rb", ".php"},
	},
	{
		ID:       "fallback-exec-usage",
		Pattern:  regexp.MustCompile(`(?i)\b(os\.system|subprocess\.call|exec\.Command|child_process\.exec)\s*\(`),
		Message:  "Shell command execution — verify inputs are sanitized",
		Severity: SeverityWarning,
		FileExts: []string{".go", ".py", ".js", ".ts", ".rb"},
	},

	// ─── Path traversal ─────────────────────────────────────────
	{
		ID:       "fallback-path-traversal",
		Pattern:  regexp.MustCompile(`\.\./`),
		Message:  "Path traversal pattern detected — verify input validation",
		Severity: SeverityWarning,
	},

	// ─── Crypto ─────────────────────────────────────────────────
	{
		ID:       "fallback-weak-hash",
		Pattern:  regexp.MustCompile(`(?i)\b(md5|sha1)\s*[\.(]`),
		Message:  "Weak hash function (MD5/SHA1) — use SHA-256 or stronger",
		Severity: SeverityWarning,
		FileExts: []string{".go", ".py", ".js", ".ts", ".java", ".rb", ".php"},
	},

	// ─── Debug / unsafe defaults ────────────────────────────────
	{
		ID:       "fallback-debug-true",
		Pattern:  regexp.MustCompile(`(?i)(debug|DEBUG)\s*[:=]\s*(true|True|1|"true")`),
		Message:  "Debug mode enabled — ensure this is not deployed to production",
		Severity: SeverityWarning,
	},
	{
		ID:       "fallback-cors-wildcard",
		Pattern:  regexp.MustCompile(`(?i)(access-control-allow-origin|cors.*origin)\s*[:=]\s*["']\*["']`),
		Message:  "CORS wildcard origin — allows any domain to make requests",
		Severity: SeverityWarning,
	},
}

// RunFallback executes hardcoded regex rules against added lines from diffs.
// This is the zero-dependency backstop when semgrep is unavailable.
func RunFallback(diffs []diff.FileDiff) []Finding {
	var findings []Finding

	for _, fd := range diffs {
		ext := fileExtension(fd.Path)

		for _, hunk := range fd.Hunks {
			for _, line := range hunk.Lines {
				if line.Kind != diff.KindAdd {
					continue
				}

				for _, rule := range fallbackRules {
					// Check file extension filter
					if len(rule.FileExts) > 0 && !containsExt(rule.FileExts, ext) {
						continue
					}

					if rule.Pattern.MatchString(line.Content) {
						findings = append(findings, Finding{
							RuleID:   rule.ID,
							Path:     fd.Path,
							Line:     line.Number,
							Message:  rule.Message,
							Severity: rule.Severity,
							Content:  strings.TrimSpace(line.Content),
							Source:   "fallback",
						})
					}
				}
			}
		}
	}

	return findings
}

func fileExtension(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return path[idx:]
}

func containsExt(exts []string, ext string) bool {
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}

// RuleInfo holds exported metadata about a fallback rule.
type RuleInfo struct {
	ID       string
	Message  string
	Severity Severity
	FileExts []string
}

// ListRules returns metadata about all bundled fallback rules.
func ListRules() []RuleInfo {
	var rules []RuleInfo
	for _, r := range fallbackRules {
		rules = append(rules, RuleInfo{
			ID:       r.ID,
			Message:  r.Message,
			Severity: r.Severity,
			FileExts: r.FileExts,
		})
	}
	return rules
}

