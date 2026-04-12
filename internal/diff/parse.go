package diff

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse converts raw unified diff text into structured FileDiff slices.
func Parse(raw string) ([]FileDiff, error) {
	var diffs []FileDiff
	lines := strings.Split(raw, "\n")

	var current *FileDiff
	var currentHunk *Hunk
	newLineNum := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// New file header
		if strings.HasPrefix(line, "diff --git ") {
			if current != nil {
				if currentHunk != nil {
					current.Hunks = append(current.Hunks, *currentHunk)
					currentHunk = nil
				}
				diffs = append(diffs, *current)
			}
			current = &FileDiff{}
			continue
		}

		// Extract file path from +++ line
		if strings.HasPrefix(line, "+++ b/") {
			if current != nil {
				current.Path = strings.TrimPrefix(line, "+++ b/")
			}
			continue
		}

		// Skip --- line
		if strings.HasPrefix(line, "--- ") {
			continue
		}

		// Hunk header
		if strings.HasPrefix(line, "@@ ") {
			if current != nil && currentHunk != nil {
				current.Hunks = append(current.Hunks, *currentHunk)
			}
			h, err := parseHunkHeader(line)
			if err != nil {
				return nil, fmt.Errorf("parse hunk header line %d: %w", i+1, err)
			}
			currentHunk = &h
			newLineNum = h.NewStart
			continue
		}

		if currentHunk == nil {
			continue
		}

		// Diff content lines
		if strings.HasPrefix(line, "+") {
			currentHunk.Lines = append(currentHunk.Lines, Line{
				Kind:    KindAdd,
				Content: strings.TrimPrefix(line, "+"),
				Number:  newLineNum,
			})
			newLineNum++
		} else if strings.HasPrefix(line, "-") {
			currentHunk.Lines = append(currentHunk.Lines, Line{
				Kind:    KindDelete,
				Content: strings.TrimPrefix(line, "-"),
				Number:  0,
			})
		} else if strings.HasPrefix(line, " ") {
			currentHunk.Lines = append(currentHunk.Lines, Line{
				Kind:    KindContext,
				Content: strings.TrimPrefix(line, " "),
				Number:  newLineNum,
			})
			newLineNum++
		}
	}

	// Flush final file + hunk
	if current != nil {
		if currentHunk != nil {
			current.Hunks = append(current.Hunks, *currentHunk)
		}
		diffs = append(diffs, *current)
	}

	return diffs, nil
}

// parseHunkHeader extracts start/count from a unified diff hunk header.
// Format: @@ -oldStart,oldCount +newStart,newCount @@
func parseHunkHeader(line string) (Hunk, error) {
	// Strip @@ markers
	line = strings.TrimPrefix(line, "@@ ")
	atIdx := strings.Index(line, " @@")
	if atIdx >= 0 {
		line = line[:atIdx]
	}

	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return Hunk{}, fmt.Errorf("invalid hunk header: %q", line)
	}

	old := strings.TrimPrefix(parts[0], "-")
	new_ := strings.TrimPrefix(parts[1], "+")

	oldStart, oldCount, err := parseRange(old)
	if err != nil {
		return Hunk{}, err
	}
	newStart, newCount, err := parseRange(new_)
	if err != nil {
		return Hunk{}, err
	}

	return Hunk{
		OldStart: oldStart,
		OldCount: oldCount,
		NewStart: newStart,
		NewCount: newCount,
	}, nil
}

func parseRange(s string) (int, int, error) {
	parts := strings.SplitN(s, ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parse range start %q: %w", s, err)
	}
	count := 1
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("parse range count %q: %w", s, err)
		}
	}
	return start, count, nil
}
