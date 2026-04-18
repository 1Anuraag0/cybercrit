package analyzer

// Deduplicate removes findings with the same RuleID + Content combination.
// First occurrence wins.
func Deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding

	for _, f := range findings {
		key := f.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, f)
	}

	return unique
}

