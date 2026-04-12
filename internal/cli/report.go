package cli

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cybercrit/cybercrit/internal/audit"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var days int

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show security trend report from audit history",
		Long: `Analyze audit.jsonl data to show severity trends, most common rules,
bypass history, and whether your codebase security is improving or degrading.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			entries, err := audit.ReadAll(wd)
			if err != nil {
				return fmt.Errorf("read audit log: %w", err)
			}

			if len(entries) == 0 {
				fmt.Println("No audit data yet. Run `cybercrit scan` to generate findings.")
				return nil
			}

			// Filter by time window
			cutoff := time.Now().UTC().AddDate(0, 0, -days)
			var filtered []audit.Entry
			for _, e := range entries {
				t, err := time.Parse(time.RFC3339, e.Timestamp)
				if err != nil {
					continue
				}
				if t.After(cutoff) {
					filtered = append(filtered, e)
				}
			}

			if len(filtered) == 0 {
				fmt.Printf("No audit data in the last %d days.\n", days)
				return nil
			}

			// ─── Severity breakdown ────────────────────────────────
			sevCounts := map[string]int{}
			actionCounts := map[string]int{}
			ruleCounts := map[string]int{}
			sourceCounts := map[string]int{}
			bypassCount := 0

			for _, e := range filtered {
				sevCounts[e.Severity]++
				actionCounts[e.Action]++
				ruleCounts[e.RuleID]++
				sourceCounts[e.Source]++
				if e.Action == "bypass" {
					bypassCount++
				}
			}

			fmt.Printf("╔══════════════════════════════════════════╗\n")
			fmt.Printf("║     cybercrit security report            ║\n")
			fmt.Printf("║     last %d days · %d events             \n", days, len(filtered))
			fmt.Printf("╚══════════════════════════════════════════╝\n\n")

			// Severity
			fmt.Println("  Severity Breakdown:")
			for _, sev := range []string{"CRITICAL", "ERROR", "WARNING", "INFO"} {
				if c := sevCounts[sev]; c > 0 {
					bar := makeBar(c, len(filtered))
					fmt.Printf("    %-10s %3d  %s\n", sev, c, bar)
				}
			}
			fmt.Println()

			// Actions
			fmt.Println("  Actions Taken:")
			for _, act := range []string{"apply", "skip", "block", "bypass", "apply_failed"} {
				if c := actionCounts[act]; c > 0 {
					fmt.Printf("    %-14s %3d\n", act, c)
				}
			}
			fmt.Println()

			// Top rules
			fmt.Println("  Top 5 Rules:")
			type ruleCount struct {
				rule  string
				count int
			}
			var sortedRules []ruleCount
			for r, c := range ruleCounts {
				sortedRules = append(sortedRules, ruleCount{r, c})
			}
			sort.Slice(sortedRules, func(i, j int) bool {
				return sortedRules[i].count > sortedRules[j].count
			})
			for i, rc := range sortedRules {
				if i >= 5 {
					break
				}
				fmt.Printf("    %3d  %s\n", rc.count, rc.rule)
			}
			fmt.Println()

			// Sources
			fmt.Println("  Detection Sources:")
			for _, src := range []string{"semgrep", "fallback", "llm"} {
				if c := sourceCounts[src]; c > 0 {
					fmt.Printf("    %-10s %3d\n", src, c)
				}
			}
			fmt.Println()

			// Bypass warning
			if bypassCount > 0 {
				fmt.Printf("  ⚠ %d bypass(es) in this period\n\n", bypassCount)
			}

			// Trend indicator (compare first half vs second half)
			mid := len(filtered) / 2
			if mid > 0 {
				firstHalfCritical := 0
				secondHalfCritical := 0
				for i, e := range filtered {
					if e.Severity == "CRITICAL" || e.Severity == "ERROR" {
						if i < mid {
							firstHalfCritical++
						} else {
							secondHalfCritical++
						}
					}
				}

				if secondHalfCritical > firstHalfCritical {
					fmt.Println("  📈 trend: WORSENING — more critical/error findings recently")
				} else if secondHalfCritical < firstHalfCritical {
					fmt.Println("  📉 trend: IMPROVING — fewer critical/error findings recently")
				} else {
					fmt.Println("  ➡️  trend: STABLE")
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 30, "number of days to include in the report")

	return cmd
}

func makeBar(count, total int) string {
	if total == 0 {
		return ""
	}
	width := 20
	filled := (count * width) / total
	if filled < 1 {
		filled = 1
	}
	bar := ""
	for i := 0; i < filled; i++ {
		bar += "█"
	}
	for i := filled; i < width; i++ {
		bar += "░"
	}
	return bar
}
