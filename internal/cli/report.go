package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cybercrit/cybercrit/internal/audit"
	"github.com/spf13/cobra"
)

// ReportJSON is the machine-readable report format.
type ReportJSON struct {
	GeneratedAt    string            `json:"generated_at"`
	PeriodDays     int               `json:"period_days"`
	TotalEvents    int               `json:"total_events"`
	Severity       map[string]int    `json:"severity"`
	Actions        map[string]int    `json:"actions"`
	TopRules       []ruleCountJSON   `json:"top_rules"`
	Sources        map[string]int    `json:"sources"`
	BypassCount    int               `json:"bypass_count"`
	NoVerifyCount  int               `json:"no_verify_count"`
	Trend          string            `json:"trend"`
}

type ruleCountJSON struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

func newReportCmd() *cobra.Command {
	var days int
	var format string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show security trend report from audit history",
		Long: `Analyze audit.jsonl data to show severity trends, most common rules,
bypass history, and whether your codebase security is improving or degrading.

Use --format json to pipe to other tools or email to leads.`,
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
				if format == "json" {
					fmt.Println("{}")
				} else {
					fmt.Println("No audit data yet. Run `cybercrit scan` to generate findings.")
				}
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
				if format == "json" {
					fmt.Println("{}")
				} else {
					fmt.Printf("No audit data in the last %d days.\n", days)
				}
				return nil
			}

			// Compute stats
			sevCounts := map[string]int{}
			actionCounts := map[string]int{}
			ruleCounts := map[string]int{}
			sourceCounts := map[string]int{}
			bypassCount := 0
			noVerifyCount := 0

			for _, e := range filtered {
				sevCounts[e.Severity]++
				actionCounts[e.Action]++
				ruleCounts[e.RuleID]++
				sourceCounts[e.Source]++
				if e.Action == "bypass" {
					bypassCount++
				}
				if e.Action == "no-verify" {
					noVerifyCount++
				}
			}

			// Top rules sorted
			type rc struct {
				rule  string
				count int
			}
			var sortedRules []rc
			for r, c := range ruleCounts {
				sortedRules = append(sortedRules, rc{r, c})
			}
			sort.Slice(sortedRules, func(i, j int) bool {
				return sortedRules[i].count > sortedRules[j].count
			})

			// Trend
			trend := "STABLE"
			mid := len(filtered) / 2
			if mid > 0 {
				firstHalf := 0
				secondHalf := 0
				for i, e := range filtered {
					if e.Severity == "CRITICAL" || e.Severity == "ERROR" {
						if i < mid {
							firstHalf++
						} else {
							secondHalf++
						}
					}
				}
				if secondHalf > firstHalf {
					trend = "WORSENING"
				} else if secondHalf < firstHalf {
					trend = "IMPROVING"
				}
			}

			// ─── JSON output ──────────────────────────────────────
			if format == "json" {
				report := ReportJSON{
					GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
					PeriodDays:    days,
					TotalEvents:   len(filtered),
					Severity:      sevCounts,
					Actions:       actionCounts,
					Sources:       sourceCounts,
					BypassCount:   bypassCount,
					NoVerifyCount: noVerifyCount,
					Trend:         trend,
				}
				limit := 5
				if len(sortedRules) < limit {
					limit = len(sortedRules)
				}
				for _, r := range sortedRules[:limit] {
					report.TopRules = append(report.TopRules, ruleCountJSON{Rule: r.rule, Count: r.count})
				}
				data, _ := json.MarshalIndent(report, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			// ─── Human-readable output ────────────────────────────

			fmt.Printf("╔══════════════════════════════════════════╗\n")
			fmt.Printf("║     cybercrit security report            ║\n")
			fmt.Printf("║     last %d days · %d events             \n", days, len(filtered))
			fmt.Printf("╚══════════════════════════════════════════╝\n\n")

			fmt.Println("  Severity Breakdown:")
			for _, sev := range []string{"CRITICAL", "ERROR", "WARNING", "INFO"} {
				if c := sevCounts[sev]; c > 0 {
					bar := makeBar(c, len(filtered))
					fmt.Printf("    %-10s %3d  %s\n", sev, c, bar)
				}
			}
			fmt.Println()

			fmt.Println("  Actions Taken:")
			for _, act := range []string{"apply", "skip", "block", "bypass", "no-verify", "apply_failed"} {
				if c := actionCounts[act]; c > 0 {
					fmt.Printf("    %-14s %3d\n", act, c)
				}
			}
			fmt.Println()

			fmt.Println("  Top 5 Rules:")
			for i, rc := range sortedRules {
				if i >= 5 {
					break
				}
				fmt.Printf("    %3d  %s\n", rc.count, rc.rule)
			}
			fmt.Println()

			fmt.Println("  Detection Sources:")
			for _, src := range []string{"semgrep", "fallback", "llm", "post-commit-hook"} {
				if c := sourceCounts[src]; c > 0 {
					fmt.Printf("    %-10s %3d\n", src, c)
				}
			}
			fmt.Println()

			if bypassCount > 0 {
				fmt.Printf("  ⚠ %d bypass(es) in this period\n", bypassCount)
			}
			if noVerifyCount > 0 {
				fmt.Printf("  ⚠ %d --no-verify commit(s) detected\n", noVerifyCount)
			}
			if bypassCount > 0 || noVerifyCount > 0 {
				fmt.Println()
			}

			switch trend {
			case "WORSENING":
				fmt.Println("  📈 trend: WORSENING — more critical/error findings recently")
			case "IMPROVING":
				fmt.Println("  📉 trend: IMPROVING — fewer critical/error findings recently")
			default:
				fmt.Println("  ➡️  trend: STABLE")
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 30, "number of days to include in the report")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")

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
