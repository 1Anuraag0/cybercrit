package cli

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cybercrit/cybercrit/internal/analyzer"
	"github.com/cybercrit/cybercrit/internal/audit"
	"github.com/cybercrit/cybercrit/internal/bypass"
	"github.com/cybercrit/cybercrit/internal/config"
	"github.com/cybercrit/cybercrit/internal/diff"
	"github.com/cybercrit/cybercrit/internal/llm"
	"github.com/cybercrit/cybercrit/internal/patch"
	"github.com/cybercrit/cybercrit/internal/tui"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan staged changes for security issues",
		Long: `Scan staged git changes using local static analysis (Phase 1) and
optionally cloud LLM analysis (Phase 2). This is the command invoked
by the pre-commit hook.`,
		RunE: runScan,
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	start := time.Now()

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	// Load configuration
	cfg, err := config.Load(wd)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Check for bypass token
	token, _ := bypass.Consume(wd)
	if token != nil {
		fmt.Printf("⚠ bypass active (id: %s, reason: %q) — skipping analysis\n", token.ID, token.Reason)
		// Log the bypass to audit trail
		if logger, err := audit.NewLogger(wd); err == nil {
			defer logger.Close()
			_ = logger.Log(audit.Entry{
				Action:   "bypass",
				Message:  token.Reason,
				RuleID:   "bypass-" + token.ID,
				Severity: "INFO",
			})
		}
		return nil
	}

	// Get staged diffs
	diffs, err := diff.Staged(wd)
	if err != nil {
		return fmt.Errorf("get staged diffs: %w", err)
	}

	// Empty-diff fast path (CORE-05)
	if len(diffs) == 0 {
		return nil // nothing staged — exit 0 immediately
	}

	// Filter blocked extensions (CORE-06)
	var filtered []diff.FileDiff
	for _, d := range diffs {
		if cfg.IsBlocked(d.Path) {
			continue
		}
		filtered = append(filtered, d)
	}

	if len(filtered) == 0 {
		return nil
	}

	// ─── Phase 1: Local Static Analysis ────────────────────────────

	var findings []analyzer.Finding

	if cfg.Phase1.Enabled {
		if !analyzer.SemgrepAvailable() {
			fmt.Println("⚠ semgrep not found — running fallback rules (install semgrep for full coverage)")
			fallbackFindings := analyzer.RunFallback(filtered)
			findings = append(findings, fallbackFindings...)
		} else {
			semgrepFindings, err := analyzer.RunSemgrep(filtered, wd)
			if err != nil {
				fmt.Printf("⚠ semgrep error: %v (falling back to regex rules)\n", err)
				fallbackFindings := analyzer.RunFallback(filtered)
				findings = append(findings, fallbackFindings...)
			} else {
				findings = append(findings, semgrepFindings...)
			}
		}
	}

	// ─── Phase 2: LLM Analysis ────────────────────────────────────

	if cfg.Phase2.Enabled {
		client, err := llm.NewClient(cfg.Phase2.Provider, cfg.Phase2.Model, cfg.Phase2.TimeoutS)
		if err != nil {
			fmt.Printf("⚠ LLM setup error: %v (continuing without LLM analysis)\n", err)
		} else if client == nil {
			fmt.Println("⚠ no API key found — skipping LLM analysis (set GROQ_API_KEY or OPENAI_API_KEY)")
		} else {
			// Fetch related files for cross-file context (Gap 4)
			relatedFiles := llm.FetchRelatedFiles(filtered, wd)
			if len(relatedFiles) > 0 {
				fmt.Printf("  📎 %d related file(s) included for cross-file analysis\n", len(relatedFiles))
			}
			userPrompt := llm.BuildUserPromptWithContext(filtered, relatedFiles, cfg.Phase2.MaxTokens)
			response, err := client.Complete(llm.SystemPrompt(), userPrompt)
			if err != nil {
				fmt.Printf("⚠ LLM error: %v (continuing without LLM analysis)\n", err)
			} else {
				llmFindings, err := llm.ParseResponse(response, 0.70)
				if err != nil {
					fmt.Printf("⚠ LLM parse error: %v (continuing without LLM findings)\n", err)
				} else {
					findings = append(findings, llmFindings...)
				}
			}
		}
	}

	// ─── Post-processing ──────────────────────────────────────────

	suppressed := analyzer.SuppressedLines(filtered)
	findings = analyzer.FilterSuppressed(findings, suppressed)
	findings = analyzer.Deduplicate(findings)

	// ─── Results ───────────────────────────────────────────────────

	elapsed := time.Since(start)

	if len(findings) == 0 {
		fmt.Printf("cybercrit: scanned %d file(s) in %s — no issues found ✓\n",
			len(filtered), elapsed.Round(time.Millisecond))
		return nil
	}

	// Count by severity
	counts := map[analyzer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Print findings summary
	fmt.Printf("cybercrit: scanned %d file(s) in %s\n\n",
		len(filtered), elapsed.Round(time.Millisecond))

	for _, f := range findings {
		icon := severityIcon(f.Severity)
		fmt.Printf("  %s [%s] %s:%d — %s\n", icon, f.Severity, f.Path, f.Line, f.RuleID)
		fmt.Printf("    %s\n", f.Message)
		if f.Source == "llm" && f.Confidence > 0 {
			fmt.Printf("    confidence: %.0f%%\n", f.Confidence*100)
		}
		if f.Patch != "" {
			fmt.Printf("    💡 auto-fix available\n")
		}
		fmt.Println()
	}

	fmt.Printf("  %d finding(s)", len(findings))
	if c := counts[analyzer.SeverityCritical]; c > 0 {
		fmt.Printf(" · %d critical", c)
	}
	if c := counts[analyzer.SeverityError]; c > 0 {
		fmt.Printf(" · %d error", c)
	}
	if c := counts[analyzer.SeverityWarning]; c > 0 {
		fmt.Printf(" · %d warning", c)
	}
	fmt.Println()

	// ─── Interactive TUI (UI-01) ──────────────────────────────────

	// Only launch TUI if there are patchable findings and we're in a terminal
	hasPatch := false
	for _, f := range findings {
		if f.Patch != "" {
			hasPatch = true
			break
		}
	}

	if hasPatch {
		// Dry-run patches first (UI-04)
		for i := range findings {
			if findings[i].Patch != "" {
				if err := patch.DryRun(wd, findings[i].Patch); err != nil {
					// Patch would fail — clear it so TUI shows view-only
					findings[i].Patch = ""
				}
			}
		}

		fmt.Println("\n  launching interactive review...")

		model := tui.New(findings)
		p := tea.NewProgram(model)
		finalModel, err := p.Run()
		if err != nil {
			fmt.Printf("⚠ TUI error: %v\n", err)
		} else {
			m := finalModel.(tui.Model)
			results := m.Results()

			// Open audit logger (UI-03)
			logger, logErr := audit.NewLogger(wd)
			if logErr != nil {
				fmt.Printf("⚠ audit log error: %v\n", logErr)
			}
			if logger != nil {
				defer logger.Close()
			}

			// Process results
			appliedCount := 0
			for _, r := range results {
				action := "skip"
				if r.Action == tui.ActionApply && r.Finding.Patch != "" {
					// Apply the patch (UI-02)
					if err := patch.Apply(wd, r.Finding.Patch); err != nil {
						fmt.Printf("  ⚠ patch failed for %s:%d — %v\n",
							r.Finding.Path, r.Finding.Line, err)
						action = "apply_failed"
					} else {
						appliedCount++
						action = "apply"
					}
				}

				// Log to audit file
				if logger != nil {
					_ = logger.Log(audit.Entry{
						Action:   action,
						RuleID:   r.Finding.RuleID,
						Path:     r.Finding.Path,
						Line:     r.Finding.Line,
						Severity: r.Finding.Severity.String(),
						Source:   r.Finding.Source,
						Message:  r.Finding.Message,
					})
				}
			}

			if appliedCount > 0 {
				fmt.Printf("  ✓ applied %d fix(es) to staged index\n", appliedCount)
			}
		}
	}

	// Block commit on HIGH/CRITICAL findings
	blocking := counts[analyzer.SeverityError] + counts[analyzer.SeverityCritical]
	if blocking > 0 {
		fmt.Printf("\n  ✗ commit blocked: %d critical/high finding(s)\n", blocking)
		return fmt.Errorf("commit blocked: %d critical/high findings", blocking)
	}

	return nil
}

func severityIcon(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return "🔴"
	case analyzer.SeverityError:
		return "🟠"
	case analyzer.SeverityWarning:
		return "🟡"
	default:
		return "🔵"
	}
}
