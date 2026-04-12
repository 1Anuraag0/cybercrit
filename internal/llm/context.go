package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

// maxContextFiles is the maximum number of related files to include.
const maxContextFiles = 5

// maxContextFileSize is the maximum size of a context file (8KB).
const maxContextFileSize = 8192

// relatedPatterns maps import/require patterns by file extension.
var relatedPatterns = map[string][]string{
	".go":  {"import"},
	".js":  {"require(", "from '", "from \"", "import "},
	".ts":  {"require(", "from '", "from \"", "import "},
	".py":  {"import ", "from "},
	".rb":  {"require ", "require_relative "},
	".java": {"import "},
	".php": {"require ", "include ", "use "},
}

// RelatedFile holds a related file's path and content for LLM context.
type RelatedFile struct {
	Path    string
	Content string
	Reason  string // why this file was included
}

// FetchRelatedFiles finds files related to the changed files in the diff.
// This enables cross-file vulnerability detection (e.g., auth middleware + routes).
//
// Strategy:
//  1. Parse import/require statements from added lines
//  2. Look for files with matching names in the same directory or parent
//  3. Include common security-relevant files (middleware, auth, routes)
func FetchRelatedFiles(diffs []diff.FileDiff, repoRoot string) []RelatedFile {
	seen := make(map[string]bool)
	var related []RelatedFile

	// Mark changed files as seen (don't re-include them)
	for _, fd := range diffs {
		seen[fd.Path] = true
	}

	for _, fd := range diffs {
		ext := filepath.Ext(fd.Path)
		dir := filepath.Dir(fd.Path)
		patterns, ok := relatedPatterns[ext]
		if !ok {
			continue
		}

		// Scan added lines for import references
		for _, hunk := range fd.Hunks {
			for _, line := range hunk.Lines {
				if line.Kind != diff.KindAdd {
					continue
				}

				for _, pat := range patterns {
					if strings.Contains(line.Content, pat) {
						// Try to resolve the import to a file
						candidates := resolveImport(line.Content, dir, ext, repoRoot)
						for _, c := range candidates {
							if seen[c] || len(related) >= maxContextFiles {
								continue
							}
							content, err := readFileContent(filepath.Join(repoRoot, c))
							if err != nil {
								continue
							}
							seen[c] = true
							related = append(related, RelatedFile{
								Path:    c,
								Content: content,
								Reason:  fmt.Sprintf("imported by %s", fd.Path),
							})
						}
					}
				}
			}
		}

		// Also look for security-relevant sibling files
		for _, name := range []string{"middleware", "auth", "routes", "handler", "security", "permissions"} {
			pattern := filepath.Join(repoRoot, dir, name+"*")
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				rel, _ := filepath.Rel(repoRoot, m)
				rel = filepath.ToSlash(rel)
				if seen[rel] || len(related) >= maxContextFiles {
					continue
				}
				content, err := readFileContent(m)
				if err != nil {
					continue
				}
				seen[rel] = true
				related = append(related, RelatedFile{
					Path:    rel,
					Content: content,
					Reason:  "security-relevant sibling file",
				})
			}
		}
	}

	return related
}

// resolveImport attempts to turn an import statement into file paths.
func resolveImport(line, dir, ext, repoRoot string) []string {
	// Extract quoted strings from import lines
	var candidates []string
	for _, delim := range []byte{'"', '\''} {
		parts := strings.Split(line, string(delim))
		for i := 1; i < len(parts); i += 2 {
			mod := parts[i]
			// Skip stdlib / external packages
			if strings.Contains(mod, ".") || !strings.Contains(mod, "/") {
				// Try as relative path
				candidate := filepath.Join(dir, mod)
				// Add extension if missing
				if filepath.Ext(candidate) == "" {
					candidate += ext
				}
				candidate = filepath.ToSlash(candidate)
				full := filepath.Join(repoRoot, candidate)
				if _, err := os.Stat(full); err == nil {
					candidates = append(candidates, candidate)
				}
			}
		}
	}
	return candidates
}

func readFileContent(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() || info.Size() > maxContextFileSize {
		return "", fmt.Errorf("too large or directory")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
