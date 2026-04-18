package analyzer

import (
	"fmt"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

const suppressMarker = "cybercrit-ignore"

// SuppressedLines scans diff hunks for lines containing the suppression
// annotation `// cybercrit-ignore` (or `# cybercrit-ignore` for non-C-style
// languages). Returns a set of file:line keys that should be excluded.
func SuppressedLines(diffs []diff.FileDiff) map[string]bool {
	suppressed := make(map[string]bool)

	for _, fd := range diffs {
		for _, hunk := range fd.Hunks {
			for i, line := range hunk.Lines {
				if line.Kind != diff.KindAdd {
					continue
				}
				if containsSuppress(line.Content) {
					// Suppress the annotated line itself
					suppressed[suppressKey(fd.Path, line.Number)] = true

					// Also suppress the next added line (inline annotation pattern:
					// `// cybercrit-ignore` on line above the offending code)
					if i+1 < len(hunk.Lines) && hunk.Lines[i+1].Kind == diff.KindAdd {
						suppressed[suppressKey(fd.Path, hunk.Lines[i+1].Number)] = true
					}
				}
			}
		}
	}

	return suppressed
}

// FilterSuppressed removes findings whose file:line appears in the suppressed set.
func FilterSuppressed(findings []Finding, suppressed map[string]bool) []Finding {
	if len(suppressed) == 0 {
		return findings
	}

	var kept []Finding
	for _, f := range findings {
		if suppressed[suppressKey(f.Path, f.Line)] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

func containsSuppress(s string) bool {
	return strings.Contains(s, suppressMarker)
}

func suppressKey(path string, line int) string {
	return fmt.Sprintf("%s:%d", path, line)
}

