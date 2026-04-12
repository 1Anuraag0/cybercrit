package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybercrit/cybercrit/internal/diff"
)

// maxContextFiles is the maximum number of related files to include.
const maxContextFiles = 3

// maxContextLines is the maximum number of lines per related file.
const maxContextLines = 50

// maxContextFileSize is the maximum size of a context file (8KB).
const maxContextFileSize = 8192

// relatedPatterns maps import/require patterns by file extension.
var relatedPatterns = map[string][]string{
	".go":   {"import"},
	".js":   {"require(", "from '", "from \"", "import "},
	".ts":   {"require(", "from '", "from \"", "import "},
	".py":   {"import ", "from "},
	".rb":   {"require ", "require_relative "},
	".java": {"import "},
	".php":  {"require ", "include ", "use "},
}

// signaturePatterns identifies function/type/class declarations by language.
var signaturePatterns = map[string][]string{
	".go":   {"func ", "type ", "interface "},
	".js":   {"function ", "const ", "class ", "export ", "module.exports"},
	".ts":   {"function ", "const ", "class ", "export ", "interface "},
	".py":   {"def ", "class ", "@"},
	".rb":   {"def ", "class ", "module "},
	".java": {"public ", "private ", "protected ", "class ", "interface "},
	".php":  {"function ", "class ", "public ", "private "},
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
// Caps: max 3 files, 50 lines each, trimmed to function signatures only.
func FetchRelatedFiles(diffs []diff.FileDiff, repoRoot string) []RelatedFile {
	seen := make(map[string]bool)
	var related []RelatedFile

	// Mark changed files as seen (don't re-include them)
	for _, fd := range diffs {
		seen[fd.Path] = true
	}

	for _, fd := range diffs {
		if len(related) >= maxContextFiles {
			break
		}

		ext := filepath.Ext(fd.Path)
		dir := filepath.Dir(fd.Path)
		patterns, ok := relatedPatterns[ext]
		if !ok {
			continue
		}

		// Scan added lines for import references
		for _, hunk := range fd.Hunks {
			for _, line := range hunk.Lines {
				if len(related) >= maxContextFiles {
					break
				}
				if line.Kind != diff.KindAdd {
					continue
				}

				for _, pat := range patterns {
					if strings.Contains(line.Content, pat) {
						candidates := resolveImport(line.Content, dir, ext, repoRoot)
						for _, c := range candidates {
							if len(related) >= maxContextFiles {
								break
							}
							if seen[c] {
								continue
							}
							content, err := readAndTrimFile(filepath.Join(repoRoot, c), ext)
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
		if len(related) < maxContextFiles {
			for _, name := range []string{"middleware", "auth", "routes", "handler", "security", "permissions"} {
				if len(related) >= maxContextFiles {
					break
				}
				pattern := filepath.Join(repoRoot, dir, name+"*")
				matches, _ := filepath.Glob(pattern)
				for _, m := range matches {
					if len(related) >= maxContextFiles {
						break
					}
					rel, _ := filepath.Rel(repoRoot, m)
					rel = filepath.ToSlash(rel)
					if seen[rel] {
						continue
					}
					fExt := filepath.Ext(rel)
					content, err := readAndTrimFile(m, fExt)
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
	}

	return related
}

// readAndTrimFile reads a file, trims it to function/type signatures only,
// and caps at maxContextLines. This prevents token bombs.
func readAndTrimFile(path, ext string) (string, error) {
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

	lines := strings.Split(string(data), "\n")

	// Extract only signature lines (function/type/class declarations)
	sigPats := signaturePatterns[ext]
	if len(sigPats) == 0 {
		// No signature patterns — just take first maxContextLines
		if len(lines) > maxContextLines {
			lines = lines[:maxContextLines]
		}
		return strings.Join(lines, "\n"), nil
	}

	var signatures []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, pat := range sigPats {
			if strings.Contains(line, pat) {
				// Include the signature line + next 2 lines for context
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				for j := i; j < end; j++ {
					signatures = append(signatures, lines[j])
				}
				signatures = append(signatures, "") // blank separator
				break
			}
		}
		if len(signatures) >= maxContextLines {
			break
		}
	}

	if len(signatures) == 0 {
		// Fallback: first maxContextLines
		if len(lines) > maxContextLines {
			lines = lines[:maxContextLines]
		}
		return strings.Join(lines, "\n"), nil
	}

	if len(signatures) > maxContextLines {
		signatures = signatures[:maxContextLines]
	}

	return strings.Join(signatures, "\n"), nil
}

// resolveImport attempts to turn an import statement into file paths.
func resolveImport(line, dir, ext, repoRoot string) []string {
	var candidates []string
	for _, delim := range []byte{'"', '\''} {
		parts := strings.Split(line, string(delim))
		for i := 1; i < len(parts); i += 2 {
			mod := parts[i]
			if strings.Contains(mod, ".") || !strings.Contains(mod, "/") {
				candidate := filepath.Join(dir, mod)
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
